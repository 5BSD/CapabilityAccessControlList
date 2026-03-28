/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_REMOVE ioctl.
 *
 * Verifies:
 * 1. Removing a process from the access list denies future access
 */

#include "test_common.h"
#include <signal.h>

static int
test_remove_denies_access(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync1[2], sync2[2];
	char buf[8];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Two sync pipes for handshaking. */
	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	/* Fork a child using pdfork. */
	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/*
		 * Child: exec immediately to get a new token.
		 * Then wait for signals to try writes.
		 */
		close(pipe_r);
		close(sync1[1]);
		close(sync2[1]);
		signal(SIGPIPE, SIG_IGN);

		/* Move fds to known positions, avoiding close if already there. */
		if (pipe_w != 3) {
			if (dup2(pipe_w, 3) < 0)
				_exit(10);
			close(pipe_w);
		}
		if (sync1[0] != 4) {
			if (dup2(sync1[0], 4) < 0)
				_exit(11);
			close(sync1[0]);
		}
		if (sync2[0] != 5) {
			if (dup2(sync2[0], 5) < 0)
				_exit(12);
			close(sync2[0]);
		}

		/*
		 * Shell script:
		 * 1. Signal ready (write to stdout which parent reads)
		 * 2. Wait for first sync (read fd 4)
		 * 3. Try write "first" - should succeed (we're in ACL)
		 * 4. Wait for second sync (read fd 5)
		 * 5. Try write "second" - should fail (we've been removed)
		 */
		execl("/bin/sh", "sh", "-c",
		    "read x <&4; "
		    "printf first >&3 2>/dev/null || exit 1; "
		    "read x <&5; "
		    "printf second >&3 2>/dev/null && exit 2; "
		    "exit 0",
		    (char *)NULL);
		_exit(13);
	}

	/* Parent. */
	close(sync1[0]);
	close(sync2[0]);

	/* Give child time to exec and be ready. */
	usleep(100000);

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Add child to write end (child has new token from exec). */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Signal child to do first write. */
	write(sync1[1], "g", 1);
	close(sync1[1]);

	/* Read and verify first write. */
	usleep(50000);
	ret = read(pipe_r, buf, 5);
	ASSERT_EQ(ret, 5, "first read failed");
	buf[5] = '\0';
	ASSERT(strcmp(buf, "first") == 0, "wrong data on first read");

	/* Remove child from access list. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_remove failed");

	/* Signal child to try second write (should fail). */
	write(sync2[1], "g", 1);
	close(sync2[1]);

	/* Wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child access not denied after removal");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_remove ===\n");

	ret = test_remove_denies_access();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
