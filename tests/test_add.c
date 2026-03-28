/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_ADD ioctl.
 *
 * Verifies:
 * 1. Parent can add child process (by descriptor) to access list
 * 2. Child can then access the pipe
 * 3. Adding by process descriptor works correctly
 */

#include "test_common.h"

static int
test_add_child_by_procdesc(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[1];

	/* Open /dev/cacl. */
	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create the data pipe. */
	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Create a sync pipe for coordination. */
	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe for sync failed");

	/* Fork a child using pdfork. */
	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child process. */
		close(cacl_fd);
		close(pipe_r);
		close(sync_pipe[1]);

		/* Wait for parent to set up ACL. */
		ret = read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to write to the pipe - should succeed. */
		buf[0] = 'z';
		ret = write(pipe_w, buf, 1);
		if (ret == 1)
			_exit(0);	/* Success. */
		if (ret < 0 && errno == EACCES)
			_exit(2);	/* Access denied - test failed. */
		_exit(1);		/* Other error. */
	}

	/* Parent: add child to access list using process descriptor. */
	close(sync_pipe[0]);

	/* First add ourselves so we can read the result. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Add child by process descriptor. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Signal child to proceed. */
	buf[0] = 'g';
	write(sync_pipe[1], buf, 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child failed to write to pipe");

	/* Verify we received the data. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "read from pipe failed");
	ASSERT_EQ(buf[0], 'z', "wrong data received");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

static int
test_add_multiple_processes(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fds[2];
	pid_t pids[2];
	int ret, status;
	int sync_pipe[2];
	char buf[2];
	int i;

	/* Open /dev/cacl. */
	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create the data pipe. */
	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Create a sync pipe for coordination. */
	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe for sync failed");

	/* Fork two children. */
	for (i = 0; i < 2; i++) {
		pids[i] = fork_child(&proc_fds[i]);
		ASSERT(pids[i] >= 0, "pdfork failed");

		if (pids[i] == 0) {
			/* Child process. */
			close(cacl_fd);
			close(pipe_r);
			close(sync_pipe[1]);

			/* Wait for parent to set up ACL. */
			ret = read(sync_pipe[0], buf, 1);
			close(sync_pipe[0]);

			/* Try to write to the pipe. */
			buf[0] = 'a' + i;
			ret = write(pipe_w, buf, 1);
			if (ret == 1)
				_exit(0);
			if (ret < 0 && errno == EACCES)
				_exit(2);
			_exit(1);
		}
	}

	/* Parent: add both children to access list. */
	close(sync_pipe[0]);

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Add both children in one call. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, proc_fds, 2);
	ASSERT_EQ(ret, 0, "cacl_add with multiple procs failed");

	/* Signal children to proceed. */
	buf[0] = 'g';
	write(sync_pipe[1], buf, 1);
	write(sync_pipe[1], buf, 1);
	close(sync_pipe[1]);

	/* Wait for both children. */
	for (i = 0; i < 2; i++) {
		ret = waitpid(pids[i], &status, 0);
		ASSERT(ret == pids[i], "waitpid failed");
		ASSERT(WIFEXITED(status), "child did not exit normally");
		ASSERT_EQ(WEXITSTATUS(status), 0, "child failed to write");
		close(proc_fds[i]);
	}

	/* Verify we received data from both. */
	ret = read(pipe_r, buf, 2);
	ASSERT_EQ(ret, 2, "didn't receive data from both children");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_add ===\n");

	ret = test_add_child_by_procdesc();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_multiple_processes();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
