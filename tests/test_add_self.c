/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_ADD_SELF ioctl.
 *
 * Verifies:
 * 1. Process can add itself to a pipe's access list
 * 2. After adding, the process can still access the pipe
 * 3. Other processes (after exec) cannot access the pipe
 */

#include "test_common.h"

static int
test_add_self_basic(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to the pipe's access list. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Verify we can still write to the pipe. */
	buf[0] = 'x';
	ret = write(pipe_w, buf, 1);
	ASSERT_EQ(ret, 1, "write to pipe failed after add_self");

	/* Verify we can still read from the pipe. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self on read end failed");

	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "read from pipe failed after add_self");
	ASSERT_EQ(buf[0], 'x', "read wrong data");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

static int
test_add_self_denies_after_exec(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to the pipe's access list. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork and exec - the exec'd process should be denied. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: exec a shell that tries to write. */
		close(cacl_fd);
		close(pipe_r);

		/* Move pipe_w to fd 3. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);

		/*
		 * Exec shell command that tries to write to fd 3.
		 * Exit 0 if write fails (expected), exit 1 if write succeeds.
		 */
		execl("/bin/sh", "sh", "-c",
		    "echo x >&3 2>/dev/null && exit 1; exit 0",
		    (char *)NULL);
		_exit(10);
	}

	/* Parent: wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd process could write (should have been denied)");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_add_self ===\n");

	ret = test_add_self_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_self_denies_after_exec();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
