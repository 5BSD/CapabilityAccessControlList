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
 * Used by CACL_IOC_ADD_SELF and CACL_IOC_CLEAR.
 * ADD_SELF adds the calling process to access lists.
 * CLEAR empties access lists entirely.
 */
struct cacl_fds {
	int		*cf_cap_fds;	/* which descriptors to modify    */
	uint16_t	 cf_cap_count;	/* number of cap fds              */
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

/* Remove processes (by proc descriptor) from access lists. */
#define	CACL_IOC_REMOVE		_IOW('L', 3, struct cacl_members)

/* Clear all entries from access lists. */
#define	CACL_IOC_CLEAR		_IOW('L', 4, struct cacl_fds)

#endif /* _CACL_H_ */
