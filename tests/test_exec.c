/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test token change on exec.
 *
 * Verifies:
 * 1. After exec, a process gets a new token
 * 2. The exec'd process cannot access fds the pre-exec process was added to
 */

#include "test_common.h"
#include <signal.h>

/*
 * Test: Exec changes token - pre-exec write succeeds, post-exec denied.
 */
static int
test_exec_changes_token(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to the pipe. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork a child. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/*
		 * Child: before exec, we have parent's token (via fork).
		 * Write should succeed.
		 */
		close(pipe_r);
		signal(SIGPIPE, SIG_IGN);

		buf[0] = 'p';
		ret = write(pipe_w, buf, 1);
		if (ret != 1)
			_exit(1);  /* Pre-exec write failed. */

		/* Now exec - should get new token. */
		if (dup2(pipe_w, 3) < 0)
			_exit(2);
		close(pipe_w);

		/*
		 * Exec test_helper to try write on fd 3.
		 * After exec, child has new token and should be denied.
		 * No sync fd - proceed immediately.
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(3);
	}

	/* Parent: wait for child. */
	close(pipe_w);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd process could write (token didn't change)");

	/* Verify we received the pre-exec write. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "didn't receive pre-exec write");
	ASSERT_EQ(buf[0], 'p', "wrong data from pre-exec");

	/* Verify no post-exec write. */
	fcntl(pipe_r, F_SETFL, O_NONBLOCK);
	ret = read(pipe_r, buf, 1);
	ASSERT(ret <= 0, "received unexpected post-exec write");

	close(pipe_r);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_exec ===\n");

	ret = test_exec_changes_token();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
