/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Tests for CACL_IOC_LOCK (deny-all) and CACL_IOC_QUERY (membership check).
 */

#include "test_common.h"
#include <signal.h>

/* ========================================================================
 * LOCK Tests - Deny-All Mode
 * ======================================================================== */

/*
 * Test: Lock denies everyone, including the process that locked it.
 */
static int
test_lock_denies_self(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Before lock: should be able to write (default-allow). */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write before lock failed");

	/* Lock the descriptor. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* After lock: should be denied. */
	ret = write(pipe_w, "x", 1);
	ASSERT(ret < 0, "write after lock should fail");
	ASSERT_EQ(errno, EACCES, "expected EACCES after lock");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Lock then add_self restores access.
 */
static int
test_lock_then_add_self(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Lock. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Denied. */
	ret = write(pipe_w, "x", 1);
	ASSERT(ret < 0 && errno == EACCES, "should be denied after lock");

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Now allowed. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after add_self should succeed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Clear removes lock and returns to default-allow.
 */
static int
test_clear_removes_lock(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Lock. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Denied. */
	ret = write(pipe_w, "x", 1);
	ASSERT(ret < 0 && errno == EACCES, "should be denied after lock");

	/* Clear. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_clear failed");

	/* Now allowed (default-allow). */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after clear should succeed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Lock denies forked child (inherits token but ACL is empty+locked).
 */
static int
test_lock_denies_forked_child(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int sync_pipe[2];
	pid_t pid;
	int ret, status;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	/* Lock before fork. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Child tries to write - should be denied. */
		ret = write(pipe_w, "x", 1);
		_exit(ret < 0 && errno == EACCES ? 0 : 1);
	}

	close(sync_pipe[0]);
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child should be denied on locked pipe");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Lock, add child via procdesc, child can access.
 */
static int
test_lock_add_child_via_procdesc(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	int sync_pipe[2];
	pid_t pid;
	int ret, status;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	/* Lock the pipe. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Fork child with procdesc. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Child tries to write. */
		ret = write(pipe_w, "c", 1);
		_exit(ret == 1 ? 0 : 1);
	}

	close(sync_pipe[0]);

	/* Add child to ACL. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Signal child. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child should be allowed after add");

	/* Verify we received the data. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "should have received child's write");
	ASSERT_EQ(buf[0], 'c', "wrong data from child");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Lock survives across exec - exec'd process denied.
 */
static int
test_lock_denies_exec(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Lock the pipe. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(cacl_fd);
		close(pipe_r);

		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);

		/* Exec test_helper to try write. */
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	/* test_helper returns 0 if EACCES (denied), 1 if success */
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied on locked pipe");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/* ========================================================================
 * QUERY Tests - Membership Check
 * ======================================================================== */

/*
 * Test: Query returns 0 for empty ACL.
 */
static int
test_query_empty_acl(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, is_member;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Fork child with procdesc. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(50000);
		_exit(0);
	}

	/* Query child on empty ACL. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "should not be member of empty ACL");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query returns 1 after adding process.
 */
static int
test_query_after_add(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, is_member;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Fork child with procdesc. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(100000);
		_exit(0);
	}

	/* Not a member yet. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "should not be member before add");

	/* Add child. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Now a member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 1, "should be member after add");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query returns 0 after removing process.
 */
static int
test_query_after_remove(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, is_member;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(100000);
		_exit(0);
	}

	/* Add child. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Is a member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 1, "should be member after add");

	/* Remove child. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_remove failed");

	/* No longer a member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "should not be member after remove");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query returns 0 on locked ACL (empty).
 */
static int
test_query_locked_acl(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, is_member;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(50000);
		_exit(0);
	}

	/* Lock the ACL. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Query on locked ACL - should return 0 (not member). */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "should not be member of locked ACL");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query two different children, one in ACL, one not.
 * Children must exec to get different tokens (fork inherits parent's token).
 */
static int
test_query_two_children(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd1, proc_fd2;
	int sync1[2], sync2[2];
	pid_t pid1, pid2;
	int ret, status, is_member;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	/* Fork child1 - must exec to get unique token. */
	pid1 = pdfork(&proc_fd1, 0);
	ASSERT(pid1 >= 0, "pdfork1 failed");
	if (pid1 == 0) {
		close(sync1[1]);
		close(sync2[0]);
		close(sync2[1]);
		/* Move sync read end to fd 4. */
		if (dup2(sync1[0], 4) < 0)
			_exit(10);
		close(sync1[0]);
		/* Exec to get new token, then wait. */
		execl("./test_helper", "test_helper", "wait", "0", "4",
		    (char *)NULL);
		_exit(11);
	}
	close(sync1[0]);

	/* Fork child2 - must exec to get unique token. */
	pid2 = pdfork(&proc_fd2, 0);
	ASSERT(pid2 >= 0, "pdfork2 failed");
	if (pid2 == 0) {
		close(sync1[1]);
		close(sync2[1]);
		/* Move sync read end to fd 4. */
		if (dup2(sync2[0], 4) < 0)
			_exit(10);
		close(sync2[0]);
		/* Exec to get new token, then wait. */
		execl("./test_helper", "test_helper", "wait", "0", "4",
		    (char *)NULL);
		_exit(11);
	}
	close(sync2[0]);

	/* Give children time to exec. */
	usleep(50000);

	/* Add only child1 to ACL. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd1, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Query child1 - should be member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd1, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 1, "child1 should be member");

	/* Query child2 - should NOT be member (different token). */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd2, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "child2 should NOT be member");

	/* Signal children to exit. */
	buf[0] = 'x';
	write(sync1[1], buf, 1);
	write(sync2[1], buf, 1);
	close(sync1[1]);
	close(sync2[1]);

	waitpid(pid1, &status, 0);
	waitpid(pid2, &status, 0);
	close(proc_fd1);
	close(proc_fd2);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query after clear returns 0.
 */
static int
test_query_after_clear(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status, is_member;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		usleep(100000);
		_exit(0);
	}

	/* Add child. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	/* Is a member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 1, "should be member after add");

	/* Clear ACL. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_clear failed");

	/* No longer a member. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 0, "should not be member after clear");

	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Query with invalid procdesc returns EINVAL.
 */
static int
test_query_invalid_procdesc(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int is_member;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Query with pipe fd instead of procdesc. */
	ret = cacl_query(cacl_fd, pipe_w, pipe_r, &is_member);
	ASSERT(ret != 0, "query with non-procdesc should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Real-world scenario - supervisor monitors worker membership.
 * Workers must exec to get different tokens (fork inherits parent's token).
 */
static int
test_supervisor_scenario(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int worker1_fd, worker2_fd;
	int sync1[2], sync2[2];
	pid_t worker1, worker2;
	int ret, status, is_member;
	char buf[2];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	/* Supervisor locks the pipe initially - no one can use it. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Fork worker1 - must exec to get unique token. */
	worker1 = pdfork(&worker1_fd, 0);
	ASSERT(worker1 >= 0, "pdfork worker1 failed");
	if (worker1 == 0) {
		close(sync1[1]);
		close(sync2[0]);
		close(sync2[1]);
		/* Set up fds: 3=pipe_w, 4=sync_read */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		if (dup2(sync1[0], 4) < 0)
			_exit(11);
		close(pipe_w);
		close(sync1[0]);
		/* Exec test_helper: wait on sync, then try write. */
		execl("./test_helper", "test_helper", "write", "3", "4",
		    (char *)NULL);
		_exit(12);
	}
	close(sync1[0]);

	/* Fork worker2 - must exec to get unique token. */
	worker2 = pdfork(&worker2_fd, 0);
	ASSERT(worker2 >= 0, "pdfork worker2 failed");
	if (worker2 == 0) {
		close(sync1[1]);
		close(sync2[1]);
		/* Set up fds: 3=pipe_w, 4=sync_read */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		if (dup2(sync2[0], 4) < 0)
			_exit(11);
		close(pipe_w);
		close(sync2[0]);
		/* Exec test_helper: wait on sync, then try write. */
		execl("./test_helper", "test_helper", "write", "3", "4",
		    (char *)NULL);
		_exit(12);
	}
	close(sync2[0]);

	/* Give workers time to exec. */
	usleep(50000);

	/* Supervisor checks: neither worker is in ACL yet. */
	ret = cacl_query(cacl_fd, pipe_w, worker1_fd, &is_member);
	ASSERT_EQ(ret, 0, "query worker1 failed");
	ASSERT_EQ(is_member, 0, "worker1 should not be in ACL yet");

	ret = cacl_query(cacl_fd, pipe_w, worker2_fd, &is_member);
	ASSERT_EQ(ret, 0, "query worker2 failed");
	ASSERT_EQ(is_member, 0, "worker2 should not be in ACL yet");

	/* Supervisor grants access to worker1 only. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &worker1_fd, 1);
	ASSERT_EQ(ret, 0, "add worker1 failed");

	/* Verify membership. */
	ret = cacl_query(cacl_fd, pipe_w, worker1_fd, &is_member);
	ASSERT_EQ(ret, 0, "query worker1 failed");
	ASSERT_EQ(is_member, 1, "worker1 should be in ACL");

	ret = cacl_query(cacl_fd, pipe_w, worker2_fd, &is_member);
	ASSERT_EQ(ret, 0, "query worker2 failed");
	ASSERT_EQ(is_member, 0, "worker2 should NOT be in ACL");

	/* Signal workers to try their writes. */
	buf[0] = 'g';
	write(sync1[1], buf, 1);
	write(sync2[1], buf, 1);
	close(sync1[1]);
	close(sync2[1]);

	/* Worker1 should succeed (exit 1 = write succeeded). */
	waitpid(worker1, &status, 0);
	ASSERT(WIFEXITED(status), "worker1 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 1, "worker1 write should succeed");

	/* Worker2 should fail (exit 0 = EACCES). */
	waitpid(worker2, &status, 0);
	ASSERT(WIFEXITED(status), "worker2 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "worker2 should get EACCES");

	close(worker1_fd);
	close(worker2_fd);
	close(pipe_r);
	close(pipe_w);
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

	printf("=== test_lock_query ===\n");

	/* LOCK tests */
	ret = test_lock_denies_self();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_lock_then_add_self();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_clear_removes_lock();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_lock_denies_forked_child();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_lock_add_child_via_procdesc();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_lock_denies_exec();
	if (ret != TEST_PASS)
		return (ret);

	/* QUERY tests */
	ret = test_query_empty_acl();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_after_add();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_after_remove();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_locked_acl();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_two_children();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_after_clear();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_query_invalid_procdesc();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_supervisor_scenario();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
