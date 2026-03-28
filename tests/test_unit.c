/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for CACL ACL operations.
 *
 * Tests individual operations in isolation:
 * - Duplicate token add (idempotent)
 * - Remove non-existent token
 * - Clear empty ACL
 * - Add after clear
 * - Multiple adds then access check
 */

#include "test_common.h"

/*
 * Test: Adding same token twice should succeed (idempotent).
 */
static int
test_duplicate_add(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self twice - should succeed both times. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "first add_self failed");

	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "duplicate add_self should succeed");

	/* Verify we can still write. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after duplicate add failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Removing token not in ACL should succeed (no-op).
 */
static int
test_remove_nonexistent(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to ACL. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self failed");

	/* Fork a child we'll try to remove (but never added). */
	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child just exits. */
		_exit(0);
	}

	/* Remove child that was never added - should succeed. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "remove non-existent should succeed");

	/* We should still have access. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after remove non-existent failed");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Clearing an empty ACL should succeed.
 */
static int
test_clear_empty(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Clear without adding anything - should succeed. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "clear empty ACL failed");

	/* Pipe should still be accessible (empty ACL = default allow). */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after clear empty failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Add after clear should work.
 */
static int
test_add_after_clear(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "first add_self failed");

	/* Clear. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "clear failed");

	/* Add self again. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self after clear failed");

	/* Should have access. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after add-clear-add failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Multiple sequential adds and removes.
 */
static int
test_add_remove_sequence(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fds[3];
	pid_t pids[3];
	int ret, status;
	int i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Fork 3 children. */
	for (i = 0; i < 3; i++) {
		pids[i] = fork_child(&proc_fds[i]);
		ASSERT(pids[i] >= 0, "pdfork failed");
		if (pids[i] == 0) {
			/* Child waits then exits. */
			usleep(100000);
			_exit(0);
		}
	}

	/* Add all 3. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, proc_fds, 3);
	ASSERT_EQ(ret, 0, "add 3 procs failed");

	/* Remove middle one. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fds[1], 1);
	ASSERT_EQ(ret, 0, "remove middle proc failed");

	/* Remove first one. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fds[0], 1);
	ASSERT_EQ(ret, 0, "remove first proc failed");

	/* Add first one back. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fds[0], 1);
	ASSERT_EQ(ret, 0, "re-add first proc failed");

	/* Clean up children. */
	for (i = 0; i < 3; i++) {
		waitpid(pids[i], &status, 0);
		close(proc_fds[i]);
	}

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Verify ACL actually denies access.
 *
 * A process that is NOT in the ACL should be denied.
 * Since forked children inherit parent's token, we must exec to get
 * a new token that is not in the ACL.
 */
static int
test_denial_works(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add ONLY self - exec'd child will have different token. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(cacl_fd);
		close(pipe_r);

		/* Move pipe_w to fd 3 for test_helper. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);

		/*
		 * Exec test_helper - it will try to write to fd 3.
		 * After exec, child has new token and should be denied.
		 * Exit 0 = EACCES (denied, expected).
		 * Exit 1 = write succeeded (unexpected).
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);	/* exec failed */
	}

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child should have been denied");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_unit ===\n");

	ret = test_duplicate_add();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_remove_nonexistent();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_clear_empty();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_after_clear();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_remove_sequence();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_denial_works();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
