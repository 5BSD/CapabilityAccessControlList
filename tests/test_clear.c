/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_CLEAR ioctl.
 *
 * Verifies:
 * 1. Clearing an access list removes all entries
 * 2. After clear, all processes can access (default-allow)
 */

#include "test_common.h"
#include <signal.h>

static int
test_clear_restores_default_allow(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[8];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	/* Add self to the write end (restricts access). */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork and exec a child - it will have new token, be denied. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(pipe_r);
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		if (dup2(sync_pipe[0], 4) < 0)
			_exit(11);
		close(pipe_w);
		close(sync_pipe[0]);

		/*
		 * Shell script:
		 * 1. Try to write "denied" - should fail (new token, not in ACL)
		 * 2. Wait for signal
		 * 3. Try to write "allowed" - should succeed (ACL cleared)
		 */
		execl("/bin/sh", "sh", "-c",
		    "printf denied >&3 2>/dev/null && exit 1; "
		    "read x <&4; "
		    "printf allowed >&3 2>/dev/null || exit 2; "
		    "exit 0",
		    (char *)NULL);
		_exit(12);
	}

	/* Parent. */
	close(sync_pipe[0]);
	/* Keep pipe_w open - we need it for cacl_clear. */

	/* Give child time to exec and fail first write. */
	usleep(100000);

	/* Clear the access list - now everyone can access. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	close(pipe_w);
	ASSERT_EQ(ret, 0, "cacl_clear failed");

	/* Signal child to try second write. */
	buf[0] = 'g';
	write(sync_pipe[1], buf, 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child access not restored after clear");

	/* Verify we got "allowed" from the child. */
	ret = read(pipe_r, buf, 7);
	ASSERT_EQ(ret, 7, "didn't receive child's write");
	buf[7] = '\0';
	ASSERT(strcmp(buf, "allowed") == 0, "wrong data from child");

	close(pipe_r);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_clear ===\n");

	ret = test_clear_restores_default_allow();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
