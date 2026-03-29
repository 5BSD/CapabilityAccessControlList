/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
 *
 * Capability Access Control List (CACL) kernel module.
 * Controls which processes can use a file descriptor.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>
#include <sys/libkern.h>
#include <sys/imgact.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>

#include <security/mac/mac_policy.h>

/*
 * DTrace SDT probes for CACL.
 *
 * Usage:
 *   dtrace -n 'cacl::deny { printf("%s pid=%d op=%s", execname, pid, arg0); }'
 *   dtrace -n 'cacl::token-change { printf("%s pid=%d", execname, pid); }'
 */
SDT_PROVIDER_DECLARE(cacl);
SDT_PROVIDER_DEFINE(cacl);

/* Fired when access is denied: arg0 = operation name */
SDT_PROBE_DEFINE1(cacl, , , deny, "const char *");

/* Fired when a process gets a new token (exec) */
SDT_PROBE_DEFINE1(cacl, , , token__change, "uint64_t");

/* Fired when ACL is modified: arg0 = operation (add/remove/clear) */
SDT_PROBE_DEFINE1(cacl, , , acl__modify, "const char *");

#include "cacl.h"

MALLOC_DEFINE(M_CACL, "cacl", "Capability Access Control List");

/*
 * Sysctl variables for runtime configuration.
 */
static int cacl_verbose = 0;
SYSCTL_INT(_security, OID_AUTO, cacl_verbose, CTLFLAG_RW, &cacl_verbose, 0,
    "Log CACL access denials to kernel message buffer");

/*
 * Maximum number of file descriptors per ioctl call.
 * Prevents userspace from passing huge counts that cause DoS.
 */
#define	CACL_MAX_FDS	1024

/*
 * Maximum capacity for a single ACL's token list.
 * Prevents unbounded memory growth.
 */
#define	CACL_MAX_TOKENS	65536

/*
 * Token reference count hash table size (must be power of 2).
 */
#define	CACL_TOKEN_HASH_SIZE	256
#define	CACL_TOKEN_HASH(t)	((t) & (CACL_TOKEN_HASH_SIZE - 1))

/*
 * Label slot accessor macros.
 */
#define	SLOT(l)		((void *)mac_label_get((l), cacl_slot))
#define	SLOT_SET(l, v)	mac_label_set((l), cacl_slot, (intptr_t)(v))

/*
 * ACL entry flags.
 */
#define	CACL_ENTRY_AUTO_CLEANUP	0x01	/* remove when token refcount hits 0 */

/*
 * Token reference tracking.
 * Tracks how many credentials currently hold each token.
 * Used for lazy cleanup of auto_cleanup ACL entries.
 */
struct cacl_token_ref {
	uint64_t		 tr_token;
	uint32_t		 tr_refcount;
	LIST_ENTRY(cacl_token_ref) tr_link;
};

static struct mtx cacl_token_mtx;
static LIST_HEAD(, cacl_token_ref) cacl_token_hash[CACL_TOKEN_HASH_SIZE];

/*
 * ACL entry - token plus flags.
 */
struct cacl_entry {
	uint64_t	 ce_token;	/* process token                */
	uint8_t		 ce_flags;	/* CACL_ENTRY_* flags           */
};

/*
 * Access list structure - stored on object labels.
 * Protected by al_lock for modifications.
 */
struct cacl_acl {
	struct sx	 al_lock;	/* protects list modifications  */
	struct cacl_entry *al_entries;	/* array of allowed entries     */
	uint32_t	 al_count;	/* number of entries in list    */
	uint32_t	 al_capacity;	/* allocated capacity           */
	int		 al_locked;	/* if set, empty list = deny-all */
};

/*
 * Credential label - stores the process token.
 */
struct cacl_cred {
	uint64_t	cc_token;	/* unique process token */
};

/*
 * Label slot indices assigned by MAC framework.
 */
static int cacl_slot;

/*
 * Device state.
 */
static struct cdev *cacl_dev;

/*
 * Forward declarations.
 */
static void	cacl_acl_init(struct cacl_acl *acl);
static void	cacl_acl_destroy(struct cacl_acl *acl);
static int	cacl_acl_add(struct cacl_acl *acl, uint64_t token, uint8_t flags);
static int	cacl_acl_remove(struct cacl_acl *acl, uint64_t token);
static void	cacl_acl_clear(struct cacl_acl *acl);
static void	cacl_acl_lock(struct cacl_acl *acl);
static int	cacl_acl_contains(struct cacl_acl *acl, uint64_t token);
static int	cacl_acl_check(struct cacl_acl *acl, uint64_t token,
		    const char *op);
static uint64_t	cacl_new_token(void);

/* Token reference counting */
static void	cacl_token_ref_init(void);
static void	cacl_token_ref_inc(uint64_t token);
static void	cacl_token_ref_dec(uint64_t token);
static uint32_t	cacl_token_ref_get(uint64_t token);

/* ========================================================================
 * Token Reference Counting
 *
 * Tracks how many credentials currently hold each token. This is used
 * for lazy cleanup: when an ACL entry has the AUTO_CLEANUP flag and
 * its token's refcount reaches 0, the entry can be removed.
 * ======================================================================== */

static void
cacl_token_ref_init(void)
{
	int i;

	mtx_init(&cacl_token_mtx, "cacl_token", NULL, MTX_DEF);
	for (i = 0; i < CACL_TOKEN_HASH_SIZE; i++)
		LIST_INIT(&cacl_token_hash[i]);
}

/*
 * Increment reference count for a token.
 * Creates entry if it doesn't exist.
 */
static void
cacl_token_ref_inc(uint64_t token)
{
	struct cacl_token_ref *tr;
	uint32_t hash;

	if (token == 0)
		return;

	hash = CACL_TOKEN_HASH(token);
	mtx_lock(&cacl_token_mtx);

	LIST_FOREACH(tr, &cacl_token_hash[hash], tr_link) {
		if (tr->tr_token == token) {
			tr->tr_refcount++;
			mtx_unlock(&cacl_token_mtx);
			return;
		}
	}

	/* Not found - create new entry. */
	tr = malloc(sizeof(*tr), M_CACL, M_NOWAIT);
	if (tr != NULL) {
		tr->tr_token = token;
		tr->tr_refcount = 1;
		LIST_INSERT_HEAD(&cacl_token_hash[hash], tr, tr_link);
	}
	mtx_unlock(&cacl_token_mtx);
}

/*
 * Decrement reference count for a token.
 * Removes entry when refcount reaches 0.
 */
static void
cacl_token_ref_dec(uint64_t token)
{
	struct cacl_token_ref *tr;
	uint32_t hash;

	if (token == 0)
		return;

	hash = CACL_TOKEN_HASH(token);
	mtx_lock(&cacl_token_mtx);

	LIST_FOREACH(tr, &cacl_token_hash[hash], tr_link) {
		if (tr->tr_token == token) {
			if (tr->tr_refcount > 0)
				tr->tr_refcount--;
			if (tr->tr_refcount == 0) {
				LIST_REMOVE(tr, tr_link);
				free(tr, M_CACL);
			}
			mtx_unlock(&cacl_token_mtx);
			return;
		}
	}

	mtx_unlock(&cacl_token_mtx);
}

/*
 * Get current reference count for a token.
 * Returns 0 if token not found (no credentials hold it).
 */
static uint32_t
cacl_token_ref_get(uint64_t token)
{
	struct cacl_token_ref *tr;
	uint32_t hash, refcount = 0;

	if (token == 0)
		return (0);

	hash = CACL_TOKEN_HASH(token);
	mtx_lock(&cacl_token_mtx);

	LIST_FOREACH(tr, &cacl_token_hash[hash], tr_link) {
		if (tr->tr_token == token) {
			refcount = tr->tr_refcount;
			break;
		}
	}

	mtx_unlock(&cacl_token_mtx);
	return (refcount);
}

/* ========================================================================
 * Access List Operations
 * ======================================================================== */

static void
cacl_acl_init(struct cacl_acl *acl)
{

	sx_init(&acl->al_lock, "cacl_acl");
	acl->al_entries = NULL;
	acl->al_count = 0;
	acl->al_capacity = 0;
	acl->al_locked = 0;
}

static void
cacl_acl_destroy(struct cacl_acl *acl)
{

	if (acl->al_entries != NULL)
		free(acl->al_entries, M_CACL);
	sx_destroy(&acl->al_lock);
}

/*
 * Add a token to the access list. Returns 0 on success, ENOMEM on failure,
 * ENOSPC if maximum ACL size reached.
 * Caller must hold al_lock exclusively.
 */
static int
cacl_acl_add(struct cacl_acl *acl, uint64_t token, uint8_t flags)
{
	struct cacl_entry *newentries;
	uint32_t newcap;

	sx_assert(&acl->al_lock, SX_XLOCKED);

	/* Check if already present. */
	for (uint32_t i = 0; i < acl->al_count; i++) {
		if (acl->al_entries[i].ce_token == token) {
			/* Update flags if adding with different flags. */
			acl->al_entries[i].ce_flags |= flags;
			return (0);
		}
	}

	/* Enforce maximum ACL size. */
	if (acl->al_count >= CACL_MAX_TOKENS)
		return (ENOSPC);

	/* Grow if needed. */
	if (acl->al_count >= acl->al_capacity) {
		newcap = (acl->al_capacity == 0) ? 4 : acl->al_capacity * 2;
		/* Clamp to max to avoid overflow. */
		if (newcap > CACL_MAX_TOKENS)
			newcap = CACL_MAX_TOKENS;
		newentries = malloc(newcap * sizeof(struct cacl_entry), M_CACL,
		    M_WAITOK);
		if (acl->al_entries != NULL) {
			memcpy(newentries, acl->al_entries,
			    acl->al_count * sizeof(struct cacl_entry));
			free(acl->al_entries, M_CACL);
		}
		acl->al_entries = newentries;
		acl->al_capacity = newcap;
	}

	acl->al_entries[acl->al_count].ce_token = token;
	acl->al_entries[acl->al_count].ce_flags = flags;
	acl->al_count++;
	return (0);
}

/*
 * Remove a token from the access list. Returns 0 on success, ENOENT if
 * not found. Caller must hold al_lock exclusively.
 */
static int
cacl_acl_remove(struct cacl_acl *acl, uint64_t token)
{

	sx_assert(&acl->al_lock, SX_XLOCKED);

	for (uint32_t i = 0; i < acl->al_count; i++) {
		if (acl->al_entries[i].ce_token == token) {
			/* Swap with last and decrement count. */
			acl->al_entries[i] = acl->al_entries[acl->al_count - 1];
			acl->al_count--;
			return (0);
		}
	}
	return (ENOENT);
}

/*
 * Clear all tokens from the access list and return to default-allow.
 * Caller must hold al_lock exclusively.
 */
static void
cacl_acl_clear(struct cacl_acl *acl)
{

	sx_assert(&acl->al_lock, SX_XLOCKED);
	acl->al_count = 0;
	acl->al_locked = 0;
}

/*
 * Lock the access list: clear all tokens and set deny-all mode.
 * Even an empty list will deny access when locked.
 * Caller must hold al_lock exclusively.
 */
static void
cacl_acl_lock(struct cacl_acl *acl)
{

	sx_assert(&acl->al_lock, SX_XLOCKED);
	acl->al_count = 0;
	acl->al_locked = 1;
}

/*
 * Check if a token is in the access list (without enforcing).
 * Returns 1 if token is in list, 0 if not.
 * Caller must hold al_lock (shared or exclusive).
 */
static int
cacl_acl_contains(struct cacl_acl *acl, uint64_t token)
{

	for (uint32_t i = 0; i < acl->al_count; i++) {
		if (acl->al_entries[i].ce_token == token)
			return (1);
	}
	return (0);
}

/*
 * Perform lazy cleanup of stale auto_cleanup entries.
 * Removes entries where the token's refcount has dropped to 0.
 * Caller must hold al_lock exclusively.
 */
static void
cacl_acl_lazy_cleanup(struct cacl_acl *acl)
{
	uint32_t i;

	sx_assert(&acl->al_lock, SX_XLOCKED);

	i = 0;
	while (i < acl->al_count) {
		if ((acl->al_entries[i].ce_flags & CACL_ENTRY_AUTO_CLEANUP) &&
		    cacl_token_ref_get(acl->al_entries[i].ce_token) == 0) {
			/* Token is dead - remove entry. */
			acl->al_entries[i] = acl->al_entries[acl->al_count - 1];
			acl->al_count--;
			/* Don't increment i - check swapped entry. */
		} else {
			i++;
		}
	}
}

/*
 * Check if a token is in the access list.
 * Returns 0 if allowed, EACCES if denied.
 * If acl is NULL (pre-existing object), returns 0 (default-allow).
 * If list is empty and not locked, returns 0 (default-allow).
 * If list is empty and locked, returns EACCES (deny-all).
 * Performs lazy cleanup of stale auto_cleanup entries.
 * Fires DTrace probe on denial.
 */
static int
cacl_acl_check(struct cacl_acl *acl, uint64_t token, const char *op)
{
	int need_cleanup = 0;

	/* NULL label means pre-existing object - allow. */
	if (acl == NULL)
		return (0);

	/* Zero token means pre-existing credential - allow. */
	if (token == 0)
		return (0);

	sx_slock(&acl->al_lock);

	/* Quick scan to see if lazy cleanup is needed. */
	for (uint32_t i = 0; i < acl->al_count; i++) {
		if (acl->al_entries[i].ce_flags & CACL_ENTRY_AUTO_CLEANUP) {
			need_cleanup = 1;
			break;
		}
	}

	if (need_cleanup) {
		/* Upgrade to exclusive lock for cleanup. */
		sx_sunlock(&acl->al_lock);
		sx_xlock(&acl->al_lock);
		cacl_acl_lazy_cleanup(acl);
		sx_downgrade(&acl->al_lock);
	}

	/* Empty list: check if locked (deny-all) or not (default-allow). */
	if (acl->al_count == 0) {
		if (acl->al_locked) {
			sx_sunlock(&acl->al_lock);
			SDT_PROBE1(cacl, , , deny, op);
			if (cacl_verbose)
				printf("cacl: denied %s (locked)\n", op);
			return (EACCES);
		}
		sx_sunlock(&acl->al_lock);
		return (0);
	}

	for (uint32_t i = 0; i < acl->al_count; i++) {
		if (acl->al_entries[i].ce_token == token) {
			sx_sunlock(&acl->al_lock);
			return (0);
		}
	}

	sx_sunlock(&acl->al_lock);
	SDT_PROBE1(cacl, , , deny, op);
	if (cacl_verbose)
		printf("cacl: denied %s for token %016llx\n", op,
		    (unsigned long long)token);
	return (EACCES);
}

/*
 * Generate a new random token.
 */
static uint64_t
cacl_new_token(void)
{
	uint64_t token;

	arc4random_buf(&token, sizeof(token));
	/* Ensure non-zero (zero could be a sentinel). */
	while (token == 0)
		arc4random_buf(&token, sizeof(token));
	return (token);
}

/* ========================================================================
 * Label Accessors
 * ======================================================================== */

static struct cacl_cred *
cacl_cred_label(struct ucred *cred)
{

	if (cred == NULL || cred->cr_label == NULL)
		return (NULL);
	return (SLOT(cred->cr_label));
}

static struct cacl_acl *
cacl_pipe_label(struct pipepair *pp)
{

	if (pp->pp_label == NULL)
		return (NULL);
	return (SLOT(pp->pp_label));
}

static struct cacl_acl *
cacl_socket_label(struct socket *so)
{

	if (so->so_label == NULL)
		return (NULL);
	return (SLOT(so->so_label));
}

static struct cacl_acl *
cacl_posixshm_label(struct shmfd *shmfd)
{

	if (shmfd->shm_label == NULL)
		return (NULL);
	return (SLOT(shmfd->shm_label));
}

static struct cacl_acl *
cacl_vnode_label(struct vnode *vp)
{

	if (vp->v_label == NULL)
		return (NULL);
	return (SLOT(vp->v_label));
}

/* ========================================================================
 * MACF Credential Hooks
 * ======================================================================== */

static void
cacl_cred_init_label(struct label *label)
{
	struct cacl_cred *cc;

	cc = malloc(sizeof(*cc), M_CACL, M_WAITOK | M_ZERO);
	/* cc_token is zero from M_ZERO - represents pre-exec credential */
	SLOT_SET(label, cc);
}

static void
cacl_cred_destroy_label(struct label *label)
{
	struct cacl_cred *cc;

	cc = SLOT(label);
	if (cc != NULL) {
		/* Decrement refcount for this token. */
		cacl_token_ref_dec(cc->cc_token);
		free(cc, M_CACL);
	}
	SLOT_SET(label, NULL);
}

static void
cacl_cred_create_init(struct ucred *cred)
{
	struct cacl_cred *cc;

	cc = cacl_cred_label(cred);
	if (cc != NULL) {
		cc->cc_token = cacl_new_token();
		cacl_token_ref_inc(cc->cc_token);
	}
}

static void
cacl_cred_create_swapper(struct ucred *cred)
{
	struct cacl_cred *cc;

	cc = cacl_cred_label(cred);
	if (cc != NULL) {
		cc->cc_token = cacl_new_token();
		cacl_token_ref_inc(cc->cc_token);
	}
}

static void
cacl_cred_copy_label(struct label *src, struct label *dest)
{
	struct cacl_cred *scc, *dcc;

	scc = SLOT(src);
	dcc = SLOT(dest);

	/* Handle pre-existing credentials without our label. */
	if (dcc == NULL)
		return;
	if (scc == NULL) {
		dcc->cc_token = cacl_new_token();
		cacl_token_ref_inc(dcc->cc_token);
		return;
	}

	/* Fork: child inherits parent's token. Increment refcount. */
	dcc->cc_token = scc->cc_token;
	cacl_token_ref_inc(dcc->cc_token);
}

/*
 * Indicate that we always want to transition credentials on exec.
 * This is required for cacl_execve_transition to be called.
 */
static int
cacl_execve_will_transition(struct ucred *old __unused,
    struct vnode *vp __unused, struct label *vplabel __unused,
    struct label *interpvplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{

	/* Always transition - every exec gets a new token. */
	return (1);
}

/*
 * Called during exec to transition credentials.
 * Assign a new token to the new credential so exec'd processes
 * cannot use the pre-exec process's access rights.
 *
 * Note: The new credential was created by copying from old, so
 * cc_token was copied and its refcount was already incremented
 * in cred_copy_label. We need to decrement that old token's
 * refcount before assigning a new one.
 */
static void
cacl_execve_transition(struct ucred *old __unused, struct ucred *new,
    struct vnode *vp __unused, struct label *vplabel __unused,
    struct label *interpvplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{
	struct cacl_cred *cc;

	cc = cacl_cred_label(new);
	if (cc != NULL) {
		/* Decrement refcount for the inherited token. */
		cacl_token_ref_dec(cc->cc_token);
		/* Assign new token and increment its refcount. */
		cc->cc_token = cacl_new_token();
		cacl_token_ref_inc(cc->cc_token);
		SDT_PROBE1(cacl, , , token__change, cc->cc_token);
	}
}

/* ========================================================================
 * MACF Object Label Hooks - Pipe
 * ======================================================================== */

static void
cacl_pipe_init_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = malloc(sizeof(*acl), M_CACL, M_WAITOK);
	cacl_acl_init(acl);
	SLOT_SET(label, acl);
}

static void
cacl_pipe_destroy_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = SLOT(label);
	if (acl != NULL) {
		cacl_acl_destroy(acl);
		free(acl, M_CACL);
	}
	SLOT_SET(label, NULL);
}

/* ========================================================================
 * MACF Object Label Hooks - Socket
 * ======================================================================== */

static int
cacl_socket_init_label(struct label *label, int flag __unused)
{
	struct cacl_acl *acl;

	acl = malloc(sizeof(*acl), M_CACL, M_WAITOK);
	cacl_acl_init(acl);
	SLOT_SET(label, acl);
	return (0);
}

static void
cacl_socket_destroy_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = SLOT(label);
	if (acl != NULL) {
		cacl_acl_destroy(acl);
		free(acl, M_CACL);
	}
	SLOT_SET(label, NULL);
}

/* ========================================================================
 * MACF Use-Time Enforcement Hooks - Pipe
 * ======================================================================== */

static int
cacl_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_pipe_label(pp);
	return (cacl_acl_check(acl, token, "pipe_read"));
}

static int
cacl_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_pipe_label(pp);
	return (cacl_acl_check(acl, token, "pipe_write"));
}

static int
cacl_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_pipe_label(pp);
	return (cacl_acl_check(acl, token, "pipe_stat"));
}

static int
cacl_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel __unused, unsigned long cmd __unused,
    void *data __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_pipe_label(pp);
	return (cacl_acl_check(acl, token, "pipe_ioctl"));
}

/* ========================================================================
 * MACF Use-Time Enforcement Hooks - Socket
 * ======================================================================== */

static int
cacl_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_receive"));
}

static int
cacl_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_send"));
}

static int
cacl_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_stat"));
}

static int
cacl_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel __unused, struct sockaddr *sa __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_bind"));
}

static int
cacl_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel __unused, struct sockaddr *sa __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_connect"));
}

static int
cacl_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_listen"));
}

static int
cacl_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_socket_label(so);
	return (cacl_acl_check(acl, token, "socket_accept"));
}

/* ========================================================================
 * MACF Object Label Hooks - POSIX Shared Memory
 * ======================================================================== */

static void
cacl_posixshm_init_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = malloc(sizeof(*acl), M_CACL, M_WAITOK);
	cacl_acl_init(acl);
	SLOT_SET(label, acl);
}

static void
cacl_posixshm_destroy_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = SLOT(label);
	if (acl != NULL) {
		cacl_acl_destroy(acl);
		free(acl, M_CACL);
	}
	SLOT_SET(label, NULL);
}

/* ========================================================================
 * MACF Use-Time Enforcement Hooks - POSIX Shared Memory
 * ======================================================================== */

static int
cacl_posixshm_check_mmap(struct ucred *cred, struct shmfd *shmfd,
    struct label *shmlabel __unused, int prot __unused, int flags __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_posixshm_label(shmfd);
	return (cacl_acl_check(acl, token, "shm_mmap"));
}

static int
cacl_posixshm_check_read(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct shmfd *shmfd,
    struct label *shmlabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_posixshm_label(shmfd);
	return (cacl_acl_check(acl, token, "shm_read"));
}

static int
cacl_posixshm_check_write(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct shmfd *shmfd,
    struct label *shmlabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_posixshm_label(shmfd);
	return (cacl_acl_check(acl, token, "shm_write"));
}

static int
cacl_posixshm_check_stat(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct shmfd *shmfd,
    struct label *shmlabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_posixshm_label(shmfd);
	return (cacl_acl_check(acl, token, "shm_stat"));
}

static int
cacl_posixshm_check_truncate(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct shmfd *shmfd,
    struct label *shmlabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_posixshm_label(shmfd);
	return (cacl_acl_check(acl, token, "shm_truncate"));
}

/* ========================================================================
 * MACF Object Label Hooks - Vnode (files, FIFOs, devices)
 *
 * Vnodes use lazy allocation to avoid leaks from cached vnodes.
 * The ACL is only allocated when explicitly added to via ioctl.
 * ======================================================================== */

static void
cacl_vnode_init_label(struct label *label)
{

	/* Lazy allocation - set to NULL initially. */
	SLOT_SET(label, NULL);
}

static void
cacl_vnode_destroy_label(struct label *label)
{
	struct cacl_acl *acl;

	acl = SLOT(label);
	if (acl != NULL) {
		cacl_acl_destroy(acl);
		free(acl, M_CACL);
	}
	SLOT_SET(label, NULL);
}

/* ========================================================================
 * MACF Use-Time Enforcement Hooks - Vnode
 * ======================================================================== */

static int
cacl_vnode_check_read(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct vnode *vp,
    struct label *vplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_vnode_label(vp);
	return (cacl_acl_check(acl, token, "vnode_read"));
}

static int
cacl_vnode_check_write(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct vnode *vp,
    struct label *vplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_vnode_label(vp);
	return (cacl_acl_check(acl, token, "vnode_write"));
}

static int
cacl_vnode_check_stat(struct ucred *active_cred,
    struct ucred *file_cred __unused, struct vnode *vp,
    struct label *vplabel __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(active_cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_vnode_label(vp);
	return (cacl_acl_check(acl, token, "vnode_stat"));
}

static int
cacl_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, int prot __unused, int flags __unused)
{
	struct cacl_cred *cc;
	struct cacl_acl *acl;
	uint64_t token;

	cc = cacl_cred_label(cred);
	token = (cc != NULL) ? cc->cc_token : 0;
	acl = cacl_vnode_label(vp);
	return (cacl_acl_check(acl, token, "vnode_mmap"));
}

/*
 * Note: MACF does not provide mpo_vnode_check_ioctl.
 * Use Capsicum cap_ioctls_limit() for ioctl control on devices.
 */

/* ========================================================================
 * Ioctl Helpers
 * ======================================================================== */

/*
 * Allocate and initialize ACL for a vnode (lazy allocation).
 * Returns the ACL or NULL on allocation failure.
 *
 * Note: There's a theoretical race if two threads call this simultaneously
 * on the same vnode - both could allocate and one would leak. In practice
 * this is unlikely since ACL setup is typically done by a single process.
 */
static struct cacl_acl *
cacl_vnode_alloc_acl(struct vnode *vp)
{
	struct cacl_acl *acl, *existing;

	if (vp->v_label == NULL)
		return (NULL);

	acl = SLOT(vp->v_label);
	if (acl != NULL)
		return (acl);

	acl = malloc(sizeof(*acl), M_CACL, M_NOWAIT);
	if (acl == NULL)
		return (NULL);

	cacl_acl_init(acl);

	/*
	 * Check if another thread allocated while we were in malloc.
	 * If so, free ours and use theirs.
	 */
	existing = SLOT(vp->v_label);
	if (existing != NULL) {
		cacl_acl_destroy(acl);
		free(acl, M_CACL);
		return (existing);
	}

	SLOT_SET(vp->v_label, acl);
	return (acl);
}

/*
 * Get the access list for a file descriptor.
 *
 * Parameters:
 *   fp        - file pointer (caller must hold reference)
 *   alloc     - if true, allocate ACL for vnodes if needed
 *   supported - if non-NULL, set to 1 if type is supported, 0 otherwise
 *
 * Returns:
 *   ACL pointer if found/allocated, NULL otherwise.
 *
 * To add support for new fd types:
 *   1. Add DTYPE_xxx case here
 *   2. Implement mpo_xxx_init_label and mpo_xxx_destroy_label hooks
 *   3. Implement mpo_xxx_check_* hooks for access control
 */
static struct cacl_acl *
cacl_acl_for_file(struct file *fp, int alloc, int *supported)
{
	struct cacl_acl *acl = NULL;
	int sup = 1;

	switch (fp->f_type) {
	case DTYPE_PIPE:
		if (fp->f_data != NULL) {
			struct pipe *cpipe = fp->f_data;
			acl = cacl_pipe_label(cpipe->pipe_pair);
		}
		break;
	case DTYPE_SOCKET:
		if (fp->f_data != NULL)
			acl = cacl_socket_label(fp->f_data);
		break;
	case DTYPE_SHM:
		if (fp->f_data != NULL)
			acl = cacl_posixshm_label(fp->f_data);
		break;
	case DTYPE_VNODE:
		if (fp->f_vnode != NULL) {
			if (alloc)
				acl = cacl_vnode_alloc_acl(fp->f_vnode);
			else
				acl = cacl_vnode_label(fp->f_vnode);
		}
		break;
	default:
		/* Unsupported type - no MACF hooks implemented. */
		sup = 0;
		break;
	}

	if (supported != NULL)
		*supported = sup;
	return (acl);
}

/*
 * Get the token for a process descriptor.
 * Returns 0 on failure.
 */
static uint64_t
cacl_token_for_procdesc(struct thread *td, int fd)
{
	struct proc *p;
	struct cacl_cred *cc;
	uint64_t token = 0;
	int error;

	error = procdesc_find(td, fd, &cap_no_rights, &p);
	if (error != 0)
		return (0);

	/* procdesc_find returns with the proc locked. */
	if (p->p_ucred != NULL) {
		cc = cacl_cred_label(p->p_ucred);
		if (cc != NULL)
			token = cc->cc_token;
	}
	PROC_UNLOCK(p);

	return (token);
}

/* ========================================================================
 * Ioctl Implementation
 * ======================================================================== */

static int
cacl_ioctl_add(struct thread *td, struct cacl_members *cm)
{
	struct file *capfp;
	struct cacl_acl *acl;
	uint64_t token;
	int error = 0;
	int i, j;

	if (cm->cm_cap_count == 0 || cm->cm_proc_count == 0)
		return (EINVAL);
	if (cm->cm_cap_count > CACL_MAX_FDS ||
	    cm->cm_proc_count > CACL_MAX_FDS)
		return (EINVAL);

	/* For each cap fd, add all proc tokens. */
	for (i = 0; i < cm->cm_cap_count; i++) {
		int capfd;

		error = copyin(&cm->cm_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		acl = cacl_acl_for_file(capfp, 1, NULL);
		if (acl == NULL) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}

		sx_xlock(&acl->al_lock);

		for (j = 0; j < cm->cm_proc_count; j++) {
			int procfd;

			error = copyin(&cm->cm_proc_fds[j], &procfd,
			    sizeof(procfd));
			if (error != 0)
				break;

			token = cacl_token_for_procdesc(td, procfd);
			if (token == 0) {
				error = EINVAL;
				break;
			}

			error = cacl_acl_add(acl, token, 0);
			if (error != 0)
				break;
		}

		sx_xunlock(&acl->al_lock);
		fdrop(capfp, td);

		if (error != 0)
			break;
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "add");
	return (error);
}

/*
 * Add processes to access lists with auto-cleanup flag.
 * Entries are automatically removed when no process holds the token.
 */
static int
cacl_ioctl_add_auto(struct thread *td, struct cacl_members *cm)
{
	struct file *capfp;
	struct cacl_acl *acl;
	uint64_t token;
	int error = 0;
	int i, j;

	if (cm->cm_cap_count == 0 || cm->cm_proc_count == 0)
		return (EINVAL);
	if (cm->cm_cap_count > CACL_MAX_FDS ||
	    cm->cm_proc_count > CACL_MAX_FDS)
		return (EINVAL);

	/* For each cap fd, add all proc tokens with auto-cleanup. */
	for (i = 0; i < cm->cm_cap_count; i++) {
		int capfd;

		error = copyin(&cm->cm_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		acl = cacl_acl_for_file(capfp, 1, NULL);
		if (acl == NULL) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}

		sx_xlock(&acl->al_lock);

		for (j = 0; j < cm->cm_proc_count; j++) {
			int procfd;

			error = copyin(&cm->cm_proc_fds[j], &procfd,
			    sizeof(procfd));
			if (error != 0)
				break;

			token = cacl_token_for_procdesc(td, procfd);
			if (token == 0) {
				error = EINVAL;
				break;
			}

			error = cacl_acl_add(acl, token, CACL_ENTRY_AUTO_CLEANUP);
			if (error != 0)
				break;
		}

		sx_xunlock(&acl->al_lock);
		fdrop(capfp, td);

		if (error != 0)
			break;
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "add_auto");
	return (error);
}

static int
cacl_ioctl_add_self(struct thread *td, struct cacl_fds *cf)
{
	struct file *capfp;
	struct cacl_acl *acl;
	struct cacl_cred *cc;
	uint64_t token;
	int error = 0;
	int i;

	if (cf->cf_cap_count == 0)
		return (EINVAL);
	if (cf->cf_cap_count > CACL_MAX_FDS)
		return (EINVAL);

	/* Get caller's token. */
	cc = cacl_cred_label(td->td_ucred);
	if (cc == NULL)
		return (EINVAL);
	token = cc->cc_token;
	if (token == 0)
		return (EINVAL);

	/* Add to each cap fd. */
	for (i = 0; i < cf->cf_cap_count; i++) {
		int capfd;

		error = copyin(&cf->cf_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		acl = cacl_acl_for_file(capfp, 1, NULL);
		if (acl == NULL) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}

		sx_xlock(&acl->al_lock);
		error = cacl_acl_add(acl, token, 0);
		sx_xunlock(&acl->al_lock);

		fdrop(capfp, td);

		if (error != 0)
			break;
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "add_self");
	return (error);
}

/*
 * Add calling process to access lists with auto-cleanup flag.
 * When no process holds this token anymore (all exited or exec'd),
 * the entry will be automatically removed during lazy cleanup.
 */
static int
cacl_ioctl_add_self_auto(struct thread *td, struct cacl_fds *cf)
{
	struct file *capfp;
	struct cacl_acl *acl;
	struct cacl_cred *cc;
	uint64_t token;
	int error = 0;
	int i;

	if (cf->cf_cap_count == 0)
		return (EINVAL);
	if (cf->cf_cap_count > CACL_MAX_FDS)
		return (EINVAL);

	/* Get caller's token. */
	cc = cacl_cred_label(td->td_ucred);
	if (cc == NULL)
		return (EINVAL);
	token = cc->cc_token;
	if (token == 0)
		return (EINVAL);

	/* Add to each cap fd with auto-cleanup flag. */
	for (i = 0; i < cf->cf_cap_count; i++) {
		int capfd;

		error = copyin(&cf->cf_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		acl = cacl_acl_for_file(capfp, 1, NULL);
		if (acl == NULL) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}

		sx_xlock(&acl->al_lock);
		error = cacl_acl_add(acl, token, CACL_ENTRY_AUTO_CLEANUP);
		sx_xunlock(&acl->al_lock);

		fdrop(capfp, td);

		if (error != 0)
			break;
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "add_self_auto");
	return (error);
}

static int
cacl_ioctl_remove(struct thread *td, struct cacl_members *cm)
{
	struct file *capfp;
	struct cacl_acl *acl;
	uint64_t token;
	int error = 0;
	int i, j;

	if (cm->cm_cap_count == 0 || cm->cm_proc_count == 0)
		return (EINVAL);
	if (cm->cm_cap_count > CACL_MAX_FDS ||
	    cm->cm_proc_count > CACL_MAX_FDS)
		return (EINVAL);

	/* For each cap fd, remove all proc tokens. */
	for (i = 0; i < cm->cm_cap_count; i++) {
		int capfd;

		error = copyin(&cm->cm_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		int supported;
		acl = cacl_acl_for_file(capfp, 0, &supported);
		if (!supported) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}
		if (acl == NULL) {
			/* Supported type but no ACL = nothing to remove. */
			fdrop(capfp, td);
			continue;
		}

		sx_xlock(&acl->al_lock);

		for (j = 0; j < cm->cm_proc_count; j++) {
			int procfd;

			error = copyin(&cm->cm_proc_fds[j], &procfd,
			    sizeof(procfd));
			if (error != 0)
				break;

			token = cacl_token_for_procdesc(td, procfd);
			if (token == 0) {
				error = EINVAL;
				break;
			}

			/* Ignore ENOENT - token might not be in list. */
			(void)cacl_acl_remove(acl, token);
		}

		sx_xunlock(&acl->al_lock);
		fdrop(capfp, td);

		if (error != 0)
			break;
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "remove");
	return (error);
}

static int
cacl_ioctl_clear(struct thread *td, struct cacl_fds *cf)
{
	struct file *capfp;
	struct cacl_acl *acl;
	int error = 0;
	int i;

	if (cf->cf_cap_count == 0)
		return (EINVAL);
	if (cf->cf_cap_count > CACL_MAX_FDS)
		return (EINVAL);

	for (i = 0; i < cf->cf_cap_count; i++) {
		int capfd;

		error = copyin(&cf->cf_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		int supported;
		acl = cacl_acl_for_file(capfp, 0, &supported);
		if (!supported) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}
		if (acl == NULL) {
			/* Supported type but no ACL = already clear. */
			fdrop(capfp, td);
			continue;
		}

		sx_xlock(&acl->al_lock);
		cacl_acl_clear(acl);
		sx_xunlock(&acl->al_lock);

		fdrop(capfp, td);
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "clear");
	return (error);
}

static int
cacl_ioctl_lock(struct thread *td, struct cacl_fds *cf)
{
	struct file *capfp;
	struct cacl_acl *acl;
	int error = 0;
	int i;

	if (cf->cf_cap_count == 0)
		return (EINVAL);
	if (cf->cf_cap_count > CACL_MAX_FDS)
		return (EINVAL);

	for (i = 0; i < cf->cf_cap_count; i++) {
		int capfd;

		error = copyin(&cf->cf_cap_fds[i], &capfd, sizeof(capfd));
		if (error != 0)
			return (error);

		error = fget(td, capfd, &cap_no_rights, &capfp);
		if (error != 0)
			return (error);

		/* Lock requires allocating ACL if not present. */
		acl = cacl_acl_for_file(capfp, 1, NULL);
		if (acl == NULL) {
			fdrop(capfp, td);
			return (EOPNOTSUPP);
		}

		sx_xlock(&acl->al_lock);
		cacl_acl_lock(acl);
		sx_xunlock(&acl->al_lock);

		fdrop(capfp, td);
	}

	if (error == 0)
		SDT_PROBE1(cacl, , , acl__modify, "lock");
	return (error);
}

static int
cacl_ioctl_query(struct thread *td, struct cacl_query *cq)
{
	struct file *capfp;
	struct cacl_acl *acl;
	uint64_t token;
	int error;
	int supported;

	error = fget(td, cq->cq_cap_fd, &cap_no_rights, &capfp);
	if (error != 0)
		return (error);

	acl = cacl_acl_for_file(capfp, 0, &supported);
	if (!supported) {
		fdrop(capfp, td);
		return (EOPNOTSUPP);
	}

	/* Get the token for the process descriptor. */
	token = cacl_token_for_procdesc(td, cq->cq_proc_fd);
	if (token == 0) {
		fdrop(capfp, td);
		return (EINVAL);
	}

	/* No ACL means empty list - process not in it. */
	if (acl == NULL) {
		cq->cq_result = 0;
		fdrop(capfp, td);
		return (0);
	}

	sx_slock(&acl->al_lock);
	cq->cq_result = cacl_acl_contains(acl, token);
	sx_sunlock(&acl->al_lock);

	fdrop(capfp, td);
	return (0);
}

/* ========================================================================
 * Character Device
 * ======================================================================== */

static int
cacl_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{

	switch (cmd) {
	case CACL_IOC_ADD:
		return (cacl_ioctl_add(td, (struct cacl_members *)data));

	case CACL_IOC_ADD_AUTO:
		return (cacl_ioctl_add_auto(td, (struct cacl_members *)data));

	case CACL_IOC_ADD_SELF:
		return (cacl_ioctl_add_self(td, (struct cacl_fds *)data));

	case CACL_IOC_ADD_SELF_AUTO:
		return (cacl_ioctl_add_self_auto(td, (struct cacl_fds *)data));

	case CACL_IOC_REMOVE:
		return (cacl_ioctl_remove(td, (struct cacl_members *)data));

	case CACL_IOC_CLEAR:
		return (cacl_ioctl_clear(td, (struct cacl_fds *)data));

	case CACL_IOC_LOCK:
		return (cacl_ioctl_lock(td, (struct cacl_fds *)data));

	case CACL_IOC_QUERY:
		return (cacl_ioctl_query(td, (struct cacl_query *)data));

	default:
		return (ENOTTY);
	}
}

static struct cdevsw cacl_cdevsw = {
	.d_version =	D_VERSION,
	.d_ioctl =	cacl_ioctl,
	.d_name =	"cacl",
};

/* ========================================================================
 * MAC Policy Init/Destroy
 * ======================================================================== */

static void
cacl_init(struct mac_policy_conf *mpc __unused)
{

	cacl_token_ref_init();
	cacl_dev = make_dev(&cacl_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0666, "cacl");
	printf("cacl: loaded\n");
}

static void
cacl_destroy(struct mac_policy_conf *mpc __unused)
{
	struct cacl_token_ref *tr, *tr_tmp;
	int i;

	if (cacl_dev != NULL)
		destroy_dev(cacl_dev);

	/* Clean up token reference hash table. */
	mtx_lock(&cacl_token_mtx);
	for (i = 0; i < CACL_TOKEN_HASH_SIZE; i++) {
		LIST_FOREACH_SAFE(tr, &cacl_token_hash[i], tr_link, tr_tmp) {
			LIST_REMOVE(tr, tr_link);
			free(tr, M_CACL);
		}
	}
	mtx_unlock(&cacl_token_mtx);
	mtx_destroy(&cacl_token_mtx);

	printf("cacl: unloaded\n");
}

/* ========================================================================
 * MAC Policy Definition
 * ======================================================================== */

static struct mac_policy_ops cacl_ops = {
	/* Policy init/destroy */
	.mpo_init = cacl_init,
	.mpo_destroy = cacl_destroy,

	/* Credential hooks */
	.mpo_cred_init_label = cacl_cred_init_label,
	.mpo_cred_destroy_label = cacl_cred_destroy_label,
	.mpo_cred_create_init = cacl_cred_create_init,
	.mpo_cred_create_swapper = cacl_cred_create_swapper,
	.mpo_cred_copy_label = cacl_cred_copy_label,

	/* Exec hooks - assign new token on exec */
	.mpo_vnode_execve_will_transition = cacl_execve_will_transition,
	.mpo_vnode_execve_transition = cacl_execve_transition,

	/* Pipe hooks */
	.mpo_pipe_init_label = cacl_pipe_init_label,
	.mpo_pipe_destroy_label = cacl_pipe_destroy_label,
	.mpo_pipe_check_read = cacl_pipe_check_read,
	.mpo_pipe_check_write = cacl_pipe_check_write,
	.mpo_pipe_check_stat = cacl_pipe_check_stat,
	.mpo_pipe_check_ioctl = cacl_pipe_check_ioctl,

	/* Socket hooks */
	.mpo_socket_init_label = cacl_socket_init_label,
	.mpo_socket_destroy_label = cacl_socket_destroy_label,
	.mpo_socket_check_receive = cacl_socket_check_receive,
	.mpo_socket_check_send = cacl_socket_check_send,
	.mpo_socket_check_stat = cacl_socket_check_stat,
	.mpo_socket_check_bind = cacl_socket_check_bind,
	.mpo_socket_check_connect = cacl_socket_check_connect,
	.mpo_socket_check_listen = cacl_socket_check_listen,
	.mpo_socket_check_accept = cacl_socket_check_accept,

	/* POSIX shared memory hooks */
	.mpo_posixshm_init_label = cacl_posixshm_init_label,
	.mpo_posixshm_destroy_label = cacl_posixshm_destroy_label,
	.mpo_posixshm_check_mmap = cacl_posixshm_check_mmap,
	.mpo_posixshm_check_read = cacl_posixshm_check_read,
	.mpo_posixshm_check_write = cacl_posixshm_check_write,
	.mpo_posixshm_check_stat = cacl_posixshm_check_stat,
	.mpo_posixshm_check_truncate = cacl_posixshm_check_truncate,

	/* Vnode hooks (files, FIFOs, devices) */
	.mpo_vnode_init_label = cacl_vnode_init_label,
	.mpo_vnode_destroy_label = cacl_vnode_destroy_label,
	.mpo_vnode_check_read = cacl_vnode_check_read,
	.mpo_vnode_check_write = cacl_vnode_check_write,
	.mpo_vnode_check_stat = cacl_vnode_check_stat,
	.mpo_vnode_check_mmap = cacl_vnode_check_mmap,
	/* Note: No mpo_vnode_check_ioctl exists in MACF - use Capsicum */
};

MAC_POLICY_SET(&cacl_ops, cacl, "Capability Access Control List",
    MPC_LOADTIME_FLAG_UNLOADOK, &cacl_slot);
