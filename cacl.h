/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
 *
 * Capability Access Control List (CACL) - shared definitions.
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
 * Used by CACL_IOC_ADD_SELF, CACL_IOC_CLEAR, and CACL_IOC_LOCK.
 * ADD_SELF adds the calling process to access lists.
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
 * Ioctl commands.
 *
 * All operations are batched: one ioctl can affect multiple descriptors
 * and/or multiple processes.
 */

/* Add processes (by proc descriptor) to access lists. Creates list if needed. */
#define	CACL_IOC_ADD		_IOW('L', 1, struct cacl_members)

/* Add calling process to access lists. Creates list if needed. */
#define	CACL_IOC_ADD_SELF	_IOW('L', 2, struct cacl_fds)

/*
 * Add calling process to access lists with auto-cleanup.
 * Entry is automatically removed when no process holds this token.
 */
#define	CACL_IOC_ADD_SELF_AUTO	_IOW('L', 7, struct cacl_fds)

/* Remove processes (by proc descriptor) from access lists. */
#define	CACL_IOC_REMOVE		_IOW('L', 3, struct cacl_members)

/* Clear all entries from access lists (returns to default-allow). */
#define	CACL_IOC_CLEAR		_IOW('L', 4, struct cacl_fds)

/* Lock access lists: deny all access (even when list is empty). */
#define	CACL_IOC_LOCK		_IOW('L', 5, struct cacl_fds)

/* Query if a process is in an access list. */
#define	CACL_IOC_QUERY		_IOWR('L', 6, struct cacl_query)

#endif /* _CACL_H_ */
