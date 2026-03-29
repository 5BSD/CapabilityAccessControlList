/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Helper binary for exec denial tests.
 *
 * Usage: test_helper <operation> <fd> [sync_fd]
 *
 * Operations:
 *   read          - try to read from fd
 *   write         - try to write to fd (pipe/socket)
 *   mmap          - try to mmap fd (shm/file)
 *   fstat         - try to fstat fd
 *   recv          - try to recv from socket fd
 *   ftruncate     - try to ftruncate fd (shm)
 *   wait          - just wait on sync_fd and exit 0
 *   add_self_auto - add self to fd's ACL with auto-cleanup
 *
 * If sync_fd is provided, waits for a byte on it before proceeding.
 *
 * Exit codes:
 *   0 - operation was DENIED (EACCES) - expected after exec
 *   1 - operation SUCCEEDED - unexpected, token didn't change
 *   2 - operation failed with unexpected error
 *   10+ - setup/argument errors
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../cacl.h"

/*
 * Timeout handler - exit if we wait too long for sync.
 * Prevents orphan processes from hanging forever.
 */
static void
alarm_handler(int sig __unused)
{
	_exit(99);
}


static int
try_read(int fd)
{
	char buf[1];
	ssize_t ret;

	ret = read(fd, buf, 1);
	if (ret >= 0)
		return (1);  /* Succeeded - unexpected. */
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}

static int
try_write(int fd)
{
	char buf[1] = {'x'};
	ssize_t ret;

	ret = write(fd, buf, 1);
	if (ret == 1)
		return (1);  /* Succeeded - unexpected. */
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}

static int
try_mmap(int fd)
{
	void *addr;

	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr != MAP_FAILED) {
		munmap(addr, 4096);
		return (1);  /* Succeeded - unexpected. */
	}
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}

static int
try_fstat(int fd)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	if (ret == 0)
		return (1);  /* Succeeded - unexpected. */
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}


static int
try_recv(int fd)
{
	char buf[1];
	ssize_t ret;

	ret = recv(fd, buf, 1, MSG_DONTWAIT);
	if (ret >= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
		return (1);  /* Succeeded or would block - unexpected. */
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}

static int
try_ftruncate(int fd)
{
	int ret;

	ret = ftruncate(fd, 4096);
	if (ret == 0)
		return (1);  /* Succeeded - unexpected. */
	if (errno == EACCES)
		return (0);  /* Denied - expected. */
	return (2);  /* Other error. */
}

/*
 * Add self to fd's ACL with auto-cleanup flag.
 * Returns 0 on success, 1 on failure.
 */
static int
try_add_self_auto(int fd)
{
	int cacl_fd;
	struct cacl_fds cf;
	int ret;

	cacl_fd = open("/dev/cacl", O_RDWR);
	if (cacl_fd < 0)
		return (1);

	cf.cf_cap_fds = &fd;
	cf.cf_cap_count = 1;
	ret = ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);
	close(cacl_fd);

	return (ret == 0 ? 0 : 1);
}

int
main(int argc, char *argv[])
{
	const char *op;
	int fd, sync_fd;
	char buf[1];

	if (argc < 3) {
		fprintf(stderr, "usage: %s <op> <fd> [sync_fd]\n", argv[0]);
		return (10);
	}

	/*
	 * Set a 5 second timeout to prevent orphan processes from
	 * hanging forever if the parent dies unexpectedly.
	 */
	signal(SIGALRM, alarm_handler);
	alarm(5);

	op = argv[1];
	fd = atoi(argv[2]);

	if (argc >= 4) {
		sync_fd = atoi(argv[3]);
		/* Wait for sync signal. */
		if (read(sync_fd, buf, 1) <= 0) {
			/* EOF or error - parent probably died. */
			return (98);
		}
	}

	if (strcmp(op, "read") == 0)
		return (try_read(fd));
	else if (strcmp(op, "write") == 0)
		return (try_write(fd));
	else if (strcmp(op, "mmap") == 0)
		return (try_mmap(fd));
	else if (strcmp(op, "fstat") == 0)
		return (try_fstat(fd));
	else if (strcmp(op, "recv") == 0)
		return (try_recv(fd));
	else if (strcmp(op, "ftruncate") == 0)
		return (try_ftruncate(fd));
	else if (strcmp(op, "wait") == 0)
		return (0);  /* Just exit success - used for token tests. */
	else if (strcmp(op, "add_self_auto") == 0)
		return (try_add_self_auto(fd));
	else {
		fprintf(stderr, "unknown operation: %s\n", op);
		return (12);
	}
}
