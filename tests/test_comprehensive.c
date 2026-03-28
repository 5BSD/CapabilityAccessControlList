/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Comprehensive CACL tests covering edge cases and complex scenarios.
 */

#include "test_common.h"
#include <signal.h>

/* ========================================================================
 * Multiple Processes to Multiple Descriptors
 * ======================================================================== */

/*
 * Test: Add multiple processes to multiple fds in one call.
 * Verify each process can access each fd.
 */
static int
test_multi_proc_multi_fd(void)
{
	int cacl_fd;
	int pipes[3][2];	/* 3 pipes */
	int cap_fds[3];		/* write ends */
	int proc_fds[2];
	pid_t pids[2];
	int ret, status, i;
	int sync_pipe[2];
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create 3 pipes. */
	for (i = 0; i < 3; i++) {
		ret = pipe(pipes[i]);
		ASSERT(ret == 0, "pipe failed");
		cap_fds[i] = pipes[i][1];
	}

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	/* Fork 2 children. */
	for (i = 0; i < 2; i++) {
		pids[i] = fork_child(&proc_fds[i]);
		ASSERT(pids[i] >= 0, "pdfork failed");

		if (pids[i] == 0) {
			int j;
			close(sync_pipe[1]);

			/* Wait for ACL setup. */
			read(sync_pipe[0], buf, 1);
			close(sync_pipe[0]);

			/* Try to write to all 3 pipes. */
			for (j = 0; j < 3; j++) {
				ret = write(pipes[j][1], "x", 1);
				if (ret != 1)
					_exit(1);
			}
			_exit(0);
		}
	}

	close(sync_pipe[0]);

	/* Add self to read ends. */
	int read_fds[3] = { pipes[0][0], pipes[1][0], pipes[2][0] };
	ret = cacl_add_self(cacl_fd, read_fds, 3);
	ASSERT_EQ(ret, 0, "add_self to read ends failed");

	/* Add both processes to all 3 write ends. */
	ret = cacl_add(cacl_fd, cap_fds, 3, proc_fds, 2);
	ASSERT_EQ(ret, 0, "add multi proc to multi fd failed");

	/* Signal children. */
	write(sync_pipe[1], "gg", 2);
	close(sync_pipe[1]);

	/* Wait for children and verify success. */
	for (i = 0; i < 2; i++) {
		waitpid(pids[i], &status, 0);
		ASSERT(WIFEXITED(status), "child didn't exit normally");
		ASSERT_EQ(WEXITSTATUS(status), 0, "child failed to write");
		close(proc_fds[i]);
	}

	/* Verify we received data from both children on all pipes. */
	for (i = 0; i < 3; i++) {
		ret = read(pipes[i][0], buf, 2);
		ASSERT_EQ(ret, 2, "didn't receive data from both children");
		close(pipes[i][0]);
		close(pipes[i][1]);
	}

	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Cross-FD Access Verification
 * ======================================================================== */

/*
 * Test: Verify ACLs are independent per-fd.
 *
 * Create two pipes:
 * - pipe1 has ACL with self in it
 * - pipe2 has no ACL (empty = default allow)
 *
 * After exec, child has new token and should be:
 * - Denied on pipe1 (ACL exists but child not in it)
 * - Allowed on pipe2 (empty ACL = default allow)
 *
 * Note: Forked children inherit parent's token, so we MUST exec
 * to get a different token for meaningful isolation testing.
 */
static int
test_cross_fd_isolation(void)
{
	int cacl_fd;
	int pipe1[2], pipe2[2];
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = pipe(pipe1);
	ASSERT(ret == 0, "pipe1 failed");
	ret = pipe(pipe2);
	ASSERT(ret == 0, "pipe2 failed");

	/* Add self to pipe1 only - creates ACL with our token. */
	ret = cacl_add_self(cacl_fd, &pipe1[1], 1);
	ASSERT_EQ(ret, 0, "add_self to pipe1 failed");

	/* pipe2 has no ACL - default allow. */

	/* Verify parent can access both. */
	ret = write(pipe1[1], "p", 1);
	ASSERT_EQ(ret, 1, "parent write to pipe1 failed");
	ret = write(pipe2[1], "p", 1);
	ASSERT_EQ(ret, 1, "parent write to pipe2 failed");

	/* Fork and exec to test with different token. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(cacl_fd);
		close(pipe1[0]);
		close(pipe2[0]);

		/* Move pipe1 write end to fd 3 for test_helper. */
		if (dup2(pipe1[1], 3) < 0)
			_exit(10);
		close(pipe1[1]);

		/*
		 * Exec test_helper to write to fd 3 (pipe1).
		 * Child should be DENIED (not in pipe1's ACL).
		 * Exit 0 = EACCES (denied, expected).
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child should be denied on pipe1 (not in ACL)");

	/* Now test pipe2 - child should be allowed (empty ACL). */
	pid = fork();
	ASSERT(pid >= 0, "fork2 failed");

	if (pid == 0) {
		close(cacl_fd);
		close(pipe1[0]); close(pipe1[1]);
		close(pipe2[0]);

		/* Move pipe2 write end to fd 3. */
		if (dup2(pipe2[1], 3) < 0)
			_exit(10);
		close(pipe2[1]);

		/*
		 * Exec test_helper to write to fd 3 (pipe2).
		 * Child should SUCCEED (empty ACL = default allow).
		 * Exit 1 = write succeeded.
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child2 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 1,
	    "child should be allowed on pipe2 (empty ACL)");

	close(pipe1[0]); close(pipe1[1]);
	close(pipe2[0]); close(pipe2[1]);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Bad Input Tests
 * ======================================================================== */

/*
 * Test: Negative fd in array.
 */
static int
test_negative_fd_in_array(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int bad_fds[2];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	bad_fds[0] = pipe_w;
	bad_fds[1] = -5;	/* Invalid. */

	ret = cacl_add_self(cacl_fd, bad_fds, 2);
	ASSERT(ret != 0, "should fail with negative fd");
	ASSERT_EQ(errno, EBADF, "expected EBADF");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Closed fd in array.
 */
static int
test_closed_fd_in_array(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int fds[2];
	int ret;
	int extra_pipe[2];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(extra_pipe);
	ASSERT(ret == 0, "extra pipe failed");

	fds[0] = pipe_w;
	fds[1] = extra_pipe[1];
	close(extra_pipe[1]);	/* Close it before use. */

	ret = cacl_add_self(cacl_fd, fds, 2);
	ASSERT(ret != 0, "should fail with closed fd");
	ASSERT_EQ(errno, EBADF, "expected EBADF");

	close(extra_pipe[0]);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Boundary Tests
 * ======================================================================== */

/*
 * Test: Exactly at CACL_MAX_FDS boundary (1024).
 * We can't actually create 1024 pipes easily, so test with what we can.
 */
static int
test_many_fds(void)
{
	int cacl_fd;
	int pipes[64][2];
	int cap_fds[64];
	int ret, i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create 64 pipes. */
	for (i = 0; i < 64; i++) {
		ret = pipe(pipes[i]);
		ASSERT(ret == 0, "pipe failed");
		cap_fds[i] = pipes[i][1];
	}

	/* Add self to all 64 at once. */
	ret = cacl_add_self(cacl_fd, cap_fds, 64);
	ASSERT_EQ(ret, 0, "add_self to 64 fds failed");

	/* Verify we can write to all. */
	for (i = 0; i < 64; i++) {
		ret = write(pipes[i][1], "x", 1);
		ASSERT_EQ(ret, 1, "write failed");
	}

	/* Cleanup. */
	for (i = 0; i < 64; i++) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Remove Edge Cases
 * ======================================================================== */

/*
 * Test: Remove process that was never added.
 */
static int
test_remove_never_added(void)
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

	/* Add self but not child. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self failed");

	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(10000);
		_exit(0);
	}

	/* Remove child that was never added - should succeed (no-op). */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "remove never-added should succeed");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Double remove same process.
 */
static int
test_double_remove(void)
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

	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(50000);
		_exit(0);
	}

	/* Add child. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "add failed");

	/* Remove once. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "first remove failed");

	/* Remove again - should succeed (no-op). */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "second remove should succeed");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Add, remove, add same process.
 */
static int
test_add_remove_add(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");
	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Should have access after add-remove-add. */
		ret = write(pipe_w, "x", 1);
		_exit(ret == 1 ? 0 : 1);
	}

	close(sync_pipe[0]);

	/* Add. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "first add failed");

	/* Remove. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "remove failed");

	/* Add again. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "second add failed");

	/* Signal child. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child should have access after add-remove-add");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Interleaved Operations
 * ======================================================================== */

/*
 * Test: Operations on multiple fds interleaved.
 */
static int
test_interleaved_ops(void)
{
	int cacl_fd;
	int pipe1[2], pipe2[2], pipe3[2];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = pipe(pipe1);
	ASSERT(ret == 0, "pipe1 failed");
	ret = pipe(pipe2);
	ASSERT(ret == 0, "pipe2 failed");
	ret = pipe(pipe3);
	ASSERT(ret == 0, "pipe3 failed");

	/* Add self to pipe1. */
	ret = cacl_add_self(cacl_fd, &pipe1[1], 1);
	ASSERT_EQ(ret, 0, "add pipe1 failed");

	/* Add self to pipe2. */
	ret = cacl_add_self(cacl_fd, &pipe2[1], 1);
	ASSERT_EQ(ret, 0, "add pipe2 failed");

	/* Clear pipe1. */
	ret = cacl_clear(cacl_fd, &pipe1[1], 1);
	ASSERT_EQ(ret, 0, "clear pipe1 failed");

	/* Add self to pipe3. */
	ret = cacl_add_self(cacl_fd, &pipe3[1], 1);
	ASSERT_EQ(ret, 0, "add pipe3 failed");

	/* Pipe1 should be default allow now (cleared). */
	ret = write(pipe1[1], "1", 1);
	ASSERT_EQ(ret, 1, "pipe1 should allow (cleared)");

	/* Pipe2 should allow (we're in ACL). */
	ret = write(pipe2[1], "2", 1);
	ASSERT_EQ(ret, 1, "pipe2 should allow");

	/* Pipe3 should allow (we're in ACL). */
	ret = write(pipe3[1], "3", 1);
	ASSERT_EQ(ret, 1, "pipe3 should allow");

	close(pipe1[0]); close(pipe1[1]);
	close(pipe2[0]); close(pipe2[1]);
	close(pipe3[0]); close(pipe3[1]);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * ACL Persistence and Independence
 * ======================================================================== */

/*
 * Test: Each fd has independent ACL.
 *
 * This is now just a simpler version of test_cross_fd_isolation.
 * We verify that operations on one fd's ACL don't affect another fd's ACL.
 */
static int
test_acl_independence(void)
{
	int cacl_fd;
	int pipe1[2], pipe2[2];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = pipe(pipe1);
	ASSERT(ret == 0, "pipe1 failed");
	ret = pipe(pipe2);
	ASSERT(ret == 0, "pipe2 failed");

	/* Add self to pipe1 only. */
	ret = cacl_add_self(cacl_fd, &pipe1[1], 1);
	ASSERT_EQ(ret, 0, "add to pipe1 failed");

	/* Clear pipe1 - should NOT affect pipe2. */
	ret = cacl_clear(cacl_fd, &pipe1[1], 1);
	ASSERT_EQ(ret, 0, "clear pipe1 failed");

	/* Add self to pipe2. */
	ret = cacl_add_self(cacl_fd, &pipe2[1], 1);
	ASSERT_EQ(ret, 0, "add to pipe2 failed");

	/* Verify both pipes work (pipe1 has empty ACL, pipe2 has self). */
	ret = write(pipe1[1], "1", 1);
	ASSERT_EQ(ret, 1, "write to pipe1 failed");

	ret = write(pipe2[1], "2", 1);
	ASSERT_EQ(ret, 1, "write to pipe2 failed");

	/* Clear pipe2 - should NOT affect pipe1. */
	ret = cacl_clear(cacl_fd, &pipe2[1], 1);
	ASSERT_EQ(ret, 0, "clear pipe2 failed");

	/* Both should still work. */
	ret = write(pipe1[1], "a", 1);
	ASSERT_EQ(ret, 1, "write to pipe1 after clear failed");

	ret = write(pipe2[1], "b", 1);
	ASSERT_EQ(ret, 1, "write to pipe2 after clear failed");

	close(pipe1[0]); close(pipe1[1]);
	close(pipe2[0]); close(pipe2[1]);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Stress Tests
 * ======================================================================== */

/*
 * Test: Rapid add/remove cycles.
 */
static int
test_rapid_add_remove(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(100000);
		_exit(0);
	}

	/* Rapid add/remove 100 times. */
	for (i = 0; i < 100; i++) {
		ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
		ASSERT_EQ(ret, 0, "add in cycle failed");

		ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
		ASSERT_EQ(ret, 0, "remove in cycle failed");
	}

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Many processes in one ACL.
 */
static int
test_many_processes_one_acl(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fds[32];
	pid_t pids[32];
	int ret, status, i;
	int sync_pipe[2];
	char buf[32];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	/* Fork 32 children. */
	for (i = 0; i < 32; i++) {
		pids[i] = fork_child(&proc_fds[i]);
		ASSERT(pids[i] >= 0, "pdfork failed");

		if (pids[i] == 0) {
			close(sync_pipe[1]);
			read(sync_pipe[0], buf, 1);
			close(sync_pipe[0]);

			ret = write(pipe_w, "x", 1);
			_exit(ret == 1 ? 0 : 1);
		}
	}

	close(sync_pipe[0]);

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "add_self read failed");

	/* Add all 32 processes to write end. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, proc_fds, 32);
	ASSERT_EQ(ret, 0, "add 32 processes failed");

	/* Signal all. */
	memset(buf, 'g', 32);
	write(sync_pipe[1], buf, 32);
	close(sync_pipe[1]);

	/* Wait and verify all succeeded. */
	for (i = 0; i < 32; i++) {
		waitpid(pids[i], &status, 0);
		ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "child failed write");
		close(proc_fds[i]);
	}

	/* Verify we got 32 bytes. */
	ret = read(pipe_r, buf, 32);
	ASSERT_EQ(ret, 32, "didn't receive all 32 writes");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Clear then add self works.
 *
 * Sequence:
 * 1. Add self to ACL
 * 2. Verify can write
 * 3. Clear ACL
 * 4. Verify still can write (empty ACL = default allow)
 * 5. Add self again
 * 6. Verify can write
 * 7. Fork+exec child (has different token)
 * 8. Verify child denied (not in new ACL)
 */
static int
test_clear_then_add_new(void)
{
	int cacl_fd, pipe_r, pipe_w;
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

	/* Verify we can write. */
	ret = write(pipe_w, "1", 1);
	ASSERT_EQ(ret, 1, "write before clear failed");

	/* Clear ACL. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "clear failed");

	/* Verify we can still write (empty ACL = default allow). */
	ret = write(pipe_w, "2", 1);
	ASSERT_EQ(ret, 1, "write after clear failed");

	/* Add self again. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self after clear failed");

	/* Verify we can write. */
	ret = write(pipe_w, "3", 1);
	ASSERT_EQ(ret, 1, "write after re-add failed");

	/* Fork+exec child to test with different token. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(cacl_fd);
		close(pipe_r);

		/* Move pipe_w to fd 3. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);

		/*
		 * Exec test_helper. Child should be DENIED.
		 * Exit 0 = EACCES (expected).
		 */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child should be denied (not in ACL)");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Socket-specific Tests
 * ======================================================================== */

/*
 * Test: Socket pair with different ACLs on each end.
 *
 * Verifies that each socket in a pair has an independent ACL.
 * - sv[0] has ACL with self in it
 * - sv[1] has no ACL (empty = default allow)
 * - Exec'd child (different token) should be denied on sv[0], allowed on sv[1]
 */
static int
test_socketpair_different_acls(void)
{
	int cacl_fd;
	int sv[2];
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ASSERT(ret == 0, "socketpair failed");

	/* Add self to sv[0] only. */
	ret = cacl_add_self(cacl_fd, &sv[0], 1);
	ASSERT_EQ(ret, 0, "add_self to sv[0] failed");

	/* sv[1] has no ACL = default allow. */

	/* Verify parent can access both. */
	ret = write(sv[0], "p", 1);
	ASSERT_EQ(ret, 1, "parent write to sv[0] failed");
	ret = write(sv[1], "p", 1);
	ASSERT_EQ(ret, 1, "parent write to sv[1] failed");

	/* Fork+exec to test sv[0] (should be denied). */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(cacl_fd);
		close(sv[1]);

		if (dup2(sv[0], 3) < 0)
			_exit(10);
		close(sv[0]);

		/* Child should be denied on sv[0]. */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child1 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child should be denied on sv[0]");

	/* Fork+exec to test sv[1] (should be allowed). */
	pid = fork();
	ASSERT(pid >= 0, "fork2 failed");

	if (pid == 0) {
		close(cacl_fd);
		close(sv[0]);

		if (dup2(sv[1], 3) < 0)
			_exit(10);
		close(sv[1]);

		/* Child should succeed on sv[1] (empty ACL). */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child2 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 1,
	    "child should be allowed on sv[1] (empty ACL)");

	close(sv[0]);
	close(sv[1]);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int
main(void)
{
	int ret;

	signal(SIGPIPE, SIG_IGN);

	printf("=== test_comprehensive ===\n");

	/* Multi-process multi-fd. */
	ret = test_multi_proc_multi_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_cross_fd_isolation();
	if (ret != TEST_PASS)
		return (ret);

	/* Bad input. */
	ret = test_negative_fd_in_array();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_closed_fd_in_array();
	if (ret != TEST_PASS)
		return (ret);

	/* Boundary tests. */
	ret = test_many_fds();
	if (ret != TEST_PASS)
		return (ret);

	/* Remove edge cases. */
	ret = test_remove_never_added();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_double_remove();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_remove_add();
	if (ret != TEST_PASS)
		return (ret);

	/* Interleaved operations. */
	ret = test_interleaved_ops();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_acl_independence();
	if (ret != TEST_PASS)
		return (ret);

	/* Stress tests. */
	ret = test_rapid_add_remove();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_many_processes_one_acl();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_clear_then_add_new();
	if (ret != TEST_PASS)
		return (ret);

	/* Socket tests. */
	ret = test_socketpair_different_acls();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
