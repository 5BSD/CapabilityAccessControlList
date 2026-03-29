/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
 *
 * Capability Access Control List (CACL) - shared definitions.
 *
 * All ACL entries have automatic cleanup: entries are removed when
 * no process holds the associated token (all exited or exec'd).
 */

#ifndef _CACL_H_
#define _CACL_H_

#include <sys/ioccom.h>
#include <sys/types.h>

/*
 * Ioctl argument structures.
 */

/*
 * Used by CACL_IOC_ADD and CACL_IOC_REMOVE.
 * Adds or removes processes (by process descriptor) to/from access lists
 * on the specified capability file descriptors.
 */
struct cacl_members {
	int		*cm_cap_fds;	/* which descriptors to modify    */
	uint16_t	 cm_cap_count;	/* number of cap fds              */
	int		*cm_proc_fds;	/* which processes (proc descs)   */
	uint16_t	 cm_proc_count;	/* number of proc fds             */
};

/*
 * Used by CACL_IOC_ADD_SELF, CACL_IOC_REMOVE_SELF, CACL_IOC_CLEAR, CACL_IOC_LOCK.
 * ADD_SELF adds the calling process to access lists.
 * REMOVE_SELF removes the calling process from access lists.
 * CLEAR empties access lists and returns to default-allow.
 * LOCK empties access lists and sets deny-all mode.
 */
struct cacl_fds {
	int		*cf_cap_fds;	/* which descriptors to modify    */
	uint16_t	 cf_cap_count;	/* number of cap fds              */
};

/*
 * Used by CACL_IOC_QUERY.
 * Checks if a process is in an access list.
 */
struct cacl_query {
	int		 cq_cap_fd;	/* descriptor to check            */
	int		 cq_proc_fd;	/* process descriptor to check    */
	int		 cq_result;	/* output: 1 if member, 0 if not  */
};

/*
 * Used by CACL_IOC_COUNT.
 * Returns the number of entries in an access list.
 */
struct cacl_count {
	int		 cc_cap_fd;	/* descriptor to query            */
	uint32_t	 cc_count;	/* output: number of entries      */
	int		 cc_locked;	/* output: 1 if locked, 0 if not  */
};

/*
 * Used by CACL_IOC_ADD_TIMED.
 * Adds processes with a timeout (entries expire after timeout_sec seconds).
 */
struct cacl_members_timed {
	int		*cmt_cap_fds;	 /* which descriptors to modify   */
	uint16_t	 cmt_cap_count;	 /* number of cap fds             */
	int		*cmt_proc_fds;	 /* which processes (proc descs)  */
	uint16_t	 cmt_proc_count; /* number of proc fds            */
	uint32_t	 cmt_timeout_sec;/* expiry timeout in seconds     */
};

/*
 * Used by CACL_IOC_ADD_SELF_TIMED.
 * Adds calling process with a timeout.
 */
struct cacl_fds_timed {
	int		*cft_cap_fds;	 /* which descriptors to modify   */
	uint16_t	 cft_cap_count;	 /* number of cap fds             */
	uint32_t	 cft_timeout_sec;/* expiry timeout in seconds     */
};

/*
 * Ioctl commands.
 *
 * All operations are batched: one ioctl can affect multiple descriptors
 * and/or multiple processes.
 *
 * All ADD operations create entries with automatic cleanup - entries are
 * removed when no process holds the associated token anymore.
 */

/*
 * Add processes (by proc descriptor) to access lists.
 * Entries auto-cleanup when no process holds the token.
 */
#define	CACL_IOC_ADD		_IOW('L', 1, struct cacl_members)

/*
 * Add calling process to access lists.
 * Entry auto-cleans when no process holds this token.
 */
#define	CACL_IOC_ADD_SELF	_IOW('L', 2, struct cacl_fds)

/* Remove processes (by proc descriptor) from access lists. */
#define	CACL_IOC_REMOVE		_IOW('L', 3, struct cacl_members)

/* Clear all entries from access lists (returns to default-allow). */
#define	CACL_IOC_CLEAR		_IOW('L', 4, struct cacl_fds)

/* Lock access lists: deny all access (even when list is empty). */
#define	CACL_IOC_LOCK		_IOW('L', 5, struct cacl_fds)

/* Query if a process is in an access list. */
#define	CACL_IOC_QUERY		_IOWR('L', 6, struct cacl_query)

/* Remove calling process from access lists. */
#define	CACL_IOC_REMOVE_SELF	_IOW('L', 9, struct cacl_fds)

/* Count entries in an access list. */
#define	CACL_IOC_COUNT		_IOWR('L', 10, struct cacl_count)

/*
 * Add processes with expiry timeout.
 * Entries removed after timeout OR when no process holds the token.
 */
#define	CACL_IOC_ADD_TIMED	_IOW('L', 11, struct cacl_members_timed)

/*
 * Add calling process with expiry timeout.
 * Entry removed after timeout OR when no process holds this token.
 */
#define	CACL_IOC_ADD_SELF_TIMED	_IOW('L', 12, struct cacl_fds_timed)

#endif /* _CACL_H_ */
