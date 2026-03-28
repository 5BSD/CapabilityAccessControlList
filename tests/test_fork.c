/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test token inheritance on fork.
 *
 * Verifies:
 * 1. Fork preserves the parent's token (child can access)
 * 2. Fork then exec gives new token (access denied)
 */

#include "test_common.h"
#include <signal.h>

static int
test_fork_inherits_token(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to both ends of the pipe. */
	int fds[2] = { pipe_r, pipe_w };
	ret = cacl_add_self(cacl_fd, fds, 2);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork a child. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: should inherit parent's token. */
		close(cacl_fd);

		/* Try to write to pipe - should succeed. */
		buf[0] = 'f';
		ret = write(pipe_w, buf, 1);
		if (ret != 1) {
			if (errno == EACCES)
				_exit(2);  /* Token not inherited. */
			_exit(1);
		}

		/* Try to read from pipe - should succeed. */
		ret = read(pipe_r, buf, 1);
		if (ret != 1) {
			if (errno == EACCES)
				_exit(3);
			_exit(4);
		}

		_exit(0);
	}

	/* Parent: wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child couldn't access pipe (token not inherited)");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Fork then exec loses access (new token).
 */
static int
test_fork_then_exec_loses_access(void)
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

	/* Add self to pipe_w. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork a child. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: first verify access (inherited token). */
		close(pipe_r);
		signal(SIGPIPE, SIG_IGN);

		buf[0] = 'b';
		ret = write(pipe_w, buf, 1);
		if (ret != 1)
			_exit(1);  /* Inherited token didn't work. */

		/* Now exec - token should change. */
		if (dup2(pipe_w, 3) < 0)
			_exit(2);
		close(pipe_w);

		/*
		 * Exec test_helper to try write on fd 3.
		 * After exec, child has new token and should be denied.
		 * No sync fd needed - proceed immediately.
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(3);
	}

	/* Parent. */
	close(pipe_w);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child could write (should lose access)");

	/* Verify we got the pre-exec write. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "didn't receive forked child's write");
	ASSERT_EQ(buf[0], 'b', "wrong data");

	close(pipe_r);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_fork ===\n");

	ret = test_fork_inherits_token();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_fork_then_exec_loses_access();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
