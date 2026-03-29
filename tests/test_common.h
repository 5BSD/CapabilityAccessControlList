/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CACL Test Framework - Common definitions and utilities.
 *
 * All ACL entries have automatic cleanup: entries are removed when
 * no process holds the associated token (all exited or exec'd).
 */

#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../cacl.h"

/*
 * Test result codes.
 */
#define	TEST_PASS	0
#define	TEST_FAIL	1
#define	TEST_SKIP	77

/*
 * Test assertion macros.
 */
#define	ASSERT(cond, msg) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "FAIL: %s:%d: %s\n",			\
		    __func__, __LINE__, (msg));				\
		return (TEST_FAIL);					\
	}								\
} while (0)

#define	ASSERT_EQ(a, b, msg) do {					\
	if ((a) != (b)) {						\
		fprintf(stderr, "FAIL: %s:%d: %s (got %d, expected %d)\n", \
		    __func__, __LINE__, (msg), (int)(a), (int)(b));	\
		return (TEST_FAIL);					\
	}								\
} while (0)

#define	ASSERT_NE(a, b, msg) do {					\
	if ((a) == (b)) {						\
		fprintf(stderr, "FAIL: %s:%d: %s (got %d)\n",		\
		    __func__, __LINE__, (msg), (int)(a));		\
		return (TEST_FAIL);					\
	}								\
} while (0)

#define	PASS() do {							\
	printf("PASS: %s\n", __func__);					\
	return (TEST_PASS);						\
} while (0)

/*
 * Helper to open /dev/cacl.
 */
static inline int
cacl_open(void)
{
	int fd;

	fd = open("/dev/cacl", O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			fprintf(stderr, "SKIP: /dev/cacl not found - "
			    "module not loaded?\n");
		else
			perror("open(/dev/cacl)");
	}
	return (fd);
}

/*
 * Helper to add self to a capability's access list.
 * Entry auto-cleans when no process holds this token.
 */
static inline int
cacl_add_self(int cacl_fd, int *cap_fds, int cap_count)
{
	struct cacl_fds cf;

	cf.cf_cap_fds = cap_fds;
	cf.cf_cap_count = cap_count;
	return (ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf));
}

/*
 * Helper to add processes to a capability's access list.
 * Entries auto-cleanup when no process holds the token.
 */
static inline int
cacl_add(int cacl_fd, int *cap_fds, int cap_count,
    int *proc_fds, int proc_count)
{
	struct cacl_members cm;

	cm.cm_cap_fds = cap_fds;
	cm.cm_cap_count = cap_count;
	cm.cm_proc_fds = proc_fds;
	cm.cm_proc_count = proc_count;
	return (ioctl(cacl_fd, CACL_IOC_ADD, &cm));
}

/*
 * Helper to add processes with expiry timeout.
 * Entries removed after timeout OR when no process holds the token.
 */
static inline int
cacl_add_timed(int cacl_fd, int *cap_fds, int cap_count,
    int *proc_fds, int proc_count, uint32_t timeout_sec)
{
	struct cacl_members_timed cmt;

	cmt.cmt_cap_fds = cap_fds;
	cmt.cmt_cap_count = cap_count;
	cmt.cmt_proc_fds = proc_fds;
	cmt.cmt_proc_count = proc_count;
	cmt.cmt_timeout_sec = timeout_sec;
	return (ioctl(cacl_fd, CACL_IOC_ADD_TIMED, &cmt));
}

/*
 * Helper to add self with expiry timeout.
 * Entry removed after timeout OR when no process holds this token.
 */
static inline int
cacl_add_self_timed(int cacl_fd, int *cap_fds, int cap_count,
    uint32_t timeout_sec)
{
	struct cacl_fds_timed cft;

	cft.cft_cap_fds = cap_fds;
	cft.cft_cap_count = cap_count;
	cft.cft_timeout_sec = timeout_sec;
	return (ioctl(cacl_fd, CACL_IOC_ADD_SELF_TIMED, &cft));
}

/*
 * Helper to remove processes from a capability's access list.
 */
static inline int
cacl_remove(int cacl_fd, int *cap_fds, int cap_count,
    int *proc_fds, int proc_count)
{
	struct cacl_members cm;

	cm.cm_cap_fds = cap_fds;
	cm.cm_cap_count = cap_count;
	cm.cm_proc_fds = proc_fds;
	cm.cm_proc_count = proc_count;
	return (ioctl(cacl_fd, CACL_IOC_REMOVE, &cm));
}

/*
 * Helper to remove self from a capability's access list.
 */
static inline int
cacl_remove_self(int cacl_fd, int *cap_fds, int cap_count)
{
	struct cacl_fds cf;

	cf.cf_cap_fds = cap_fds;
	cf.cf_cap_count = cap_count;
	return (ioctl(cacl_fd, CACL_IOC_REMOVE_SELF, &cf));
}

/*
 * Helper to clear a capability's access list.
 */
static inline int
cacl_clear(int cacl_fd, int *cap_fds, int cap_count)
{
	struct cacl_fds cf;

	cf.cf_cap_fds = cap_fds;
	cf.cf_cap_count = cap_count;
	return (ioctl(cacl_fd, CACL_IOC_CLEAR, &cf));
}

/*
 * Helper to lock a capability's access list (deny-all mode).
 */
static inline int
cacl_lock(int cacl_fd, int *cap_fds, int cap_count)
{
	struct cacl_fds cf;

	cf.cf_cap_fds = cap_fds;
	cf.cf_cap_count = cap_count;
	return (ioctl(cacl_fd, CACL_IOC_LOCK, &cf));
}

/*
 * Helper to query if a process is in a capability's access list.
 * Returns 0 on success, with result in *is_member (1=yes, 0=no).
 */
static inline int
cacl_query(int cacl_fd, int cap_fd, int proc_fd, int *is_member)
{
	struct cacl_query cq;
	int ret;

	cq.cq_cap_fd = cap_fd;
	cq.cq_proc_fd = proc_fd;
	cq.cq_result = 0;
	ret = ioctl(cacl_fd, CACL_IOC_QUERY, &cq);
	if (ret == 0 && is_member != NULL)
		*is_member = cq.cq_result;
	return (ret);
}

/*
 * Helper to count entries in a capability's access list.
 * Returns 0 on success, with count in *count and locked state in *locked.
 */
static inline int
cacl_count(int cacl_fd, int cap_fd, uint32_t *count, int *locked)
{
	struct cacl_count cc;
	int ret;

	cc.cc_cap_fd = cap_fd;
	cc.cc_count = 0;
	cc.cc_locked = 0;
	ret = ioctl(cacl_fd, CACL_IOC_COUNT, &cc);
	if (ret == 0) {
		if (count != NULL)
			*count = cc.cc_count;
		if (locked != NULL)
			*locked = cc.cc_locked;
	}
	return (ret);
}

/*
 * Create a pipe and return both ends.
 */
static inline int
create_pipe(int *read_fd, int *write_fd)
{
	int pipefd[2];

	if (pipe(pipefd) < 0)
		return (-1);
	*read_fd = pipefd[0];
	*write_fd = pipefd[1];
	return (0);
}

/*
 * Fork a child using pdfork and return the process descriptor.
 */
static inline int
fork_child(int *proc_fd)
{
	pid_t pid;

	pid = pdfork(proc_fd, 0);
	return (pid);
}

#endif /* _TEST_COMMON_H_ */
