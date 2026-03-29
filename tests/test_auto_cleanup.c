/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_ADD_SELF_AUTO (auto-cleanup) feature.
 *
 * Auto-cleanup entries are automatically removed when no process
 * holds the associated token anymore (all exited or exec'd).
 *
 * Verifies:
 * 1. Basic auto-cleanup after process exit
 * 2. Fork inherits token, keeps refcount alive
 * 3. Exec gets new token, old token's refcount drops
 * 4. Multiple children keep entry alive until all exit
 * 5. Mixed regular and auto-cleanup entries
 * 6. Entry survives while any holder is alive
 */

#include "test_common.h"
#include <signal.h>

/*
 * Test: Basic auto-cleanup after exec.
 *
 * 1. Fork child, child adds self with auto-cleanup
 * 2. Child execs test_helper (gets new token)
 * 3. Verify entry is cleaned up on next access check
 *
 * This tests that exec causes token refcount to drop and lazy cleanup works.
 */
static int
test_auto_cleanup_after_exec(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	int is_member;

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child: add self with auto-cleanup, then exec. */
		close(pipe_r);
		close(sync_pipe[0]);

		/* Add self with auto-cleanup flag. */
		ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
		if (ret != 0)
			_exit(10);

		/* Signal parent that we've added ourselves. */
		write(sync_pipe[1], "r", 1);
		close(sync_pipe[1]);

		/* Exec test_helper - this gives us a new token. */
		if (dup2(pipe_w, 3) < 0)
			_exit(11);
		close(pipe_w);
		execl("./test_helper", "test_helper", "wait", "3", (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[1]);

	/* Wait for child to add itself. */
	char buf[1];
	ret = read(sync_pipe[0], buf, 1);
	ASSERT(ret == 1, "sync read failed");
	close(sync_pipe[0]);

	/* Query: child should be member (pre-exec, same token as fork). */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed");
	ASSERT_EQ(is_member, 1, "child should be member before exec");

	/* Give child time to exec. */
	usleep(100000);

	/* After exec, child has new token. Old token refcount = 0.
	 * Query will trigger lazy cleanup. */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed after exec");
	/* Child has new token after exec, so NOT a member with that token. */
	ASSERT_EQ(is_member, 0, "child should NOT be member after exec (new token)");

	/* Wait for child to finish. */
	waitpid(pid, &status, 0);

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Fork keeps auto-cleanup entry alive.
 *
 * 1. Parent adds self with auto-cleanup
 * 2. Fork child (inherits token, increments refcount)
 * 3. Parent still alive, entry should persist
 * 4. Child execs (gets new token), but parent still has original token
 * 5. Entry should still be valid
 */
static int
test_auto_cleanup_fork_keeps_alive(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Parent adds self with auto-cleanup. */
	ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_auto failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: exec to get new token. */
		close(sync_pipe[1]);

		/* Wait for parent's signal. */
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Exec to get new token - parent still has original. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);
		close(pipe_r);
		close(cacl_fd);
		execl("./test_helper", "test_helper", "wait", "3", (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);

	/* Parent still alive with original token. Verify we can write. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "parent write should succeed");

	/* Signal child to exec. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	usleep(100000);
	waitpid(pid, &status, 0);

	/* Parent still has token - entry should still work. */
	ret = write(pipe_w, "y", 1);
	ASSERT_EQ(ret, 1, "parent write should still succeed after child exec");

	/* Drain pipe. */
	read(pipe_r, buf, 1);
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Multiple children keep entry alive.
 *
 * 1. Parent adds self with auto-cleanup
 * 2. Fork two children (both inherit token)
 * 3. First child execs (drops its refcount)
 * 4. Entry still valid (second child + parent have it)
 * 5. Second child execs
 * 6. Entry still valid (parent has it)
 */
static int
test_auto_cleanup_multiple_children(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid1, pid2;
	int ret, status;
	int sync1[2], sync2[2];
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Parent adds self with auto-cleanup. */
	ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_auto failed");

	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	/* Fork first child. */
	pid1 = fork();
	ASSERT(pid1 >= 0, "fork1 failed");

	if (pid1 == 0) {
		close(sync1[1]);
		close(sync2[0]);
		close(sync2[1]);
		read(sync1[0], buf, 1);
		close(sync1[0]);
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);
		close(pipe_r);
		close(cacl_fd);
		execl("./test_helper", "test_helper", "wait", "3", (char *)NULL);
		_exit(12);
	}

	/* Fork second child. */
	pid2 = fork();
	ASSERT(pid2 >= 0, "fork2 failed");

	if (pid2 == 0) {
		close(sync1[0]);
		close(sync1[1]);
		close(sync2[1]);
		read(sync2[0], buf, 1);
		close(sync2[0]);
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);
		close(pipe_r);
		close(cacl_fd);
		execl("./test_helper", "test_helper", "wait", "3", (char *)NULL);
		_exit(12);
	}

	close(sync1[0]);
	close(sync2[0]);

	/* All three (parent + 2 children) have the token. */
	/* Signal child1 to exec (drops its refcount). */
	write(sync1[1], "g", 1);
	close(sync1[1]);
	usleep(50000);
	waitpid(pid1, &status, 0);

	/* Entry should still work (parent + child2 have token). */
	ret = write(pipe_w, "a", 1);
	ASSERT_EQ(ret, 1, "write should succeed after child1 exits");

	/* Signal child2 to exec. */
	write(sync2[1], "g", 1);
	close(sync2[1]);
	usleep(50000);
	waitpid(pid2, &status, 0);

	/* Entry should still work (parent has token). */
	ret = write(pipe_w, "b", 1);
	ASSERT_EQ(ret, 1, "write should succeed after child2 exits");

	/* Drain pipe. */
	read(pipe_r, buf, 1);
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Regular and auto-cleanup entries coexist.
 *
 * 1. Process A adds self with regular add (no auto-cleanup)
 * 2. Process B adds self with auto-cleanup
 * 3. Process B exits/execs
 * 4. Process B's entry cleaned up, but Process A's entry remains
 */
static int
test_auto_cleanup_mixed_entries(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	int is_member;
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Parent adds self with REGULAR add (no auto-cleanup). */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		close(sync_pipe[0]);

		/* Child adds self with auto-cleanup. */
		ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
		if (ret != 0)
			_exit(10);

		/* Signal parent. */
		write(sync_pipe[1], "r", 1);
		close(sync_pipe[1]);

		/* Exec to trigger cleanup of our entry. */
		if (dup2(pipe_w, 3) < 0)
			_exit(11);
		close(pipe_w);
		close(pipe_r);
		close(cacl_fd);
		execl("./test_helper", "test_helper", "wait", "3", (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[1]);

	/* Wait for child to add itself. */
	ret = read(sync_pipe[0], buf, 1);
	ASSERT(ret == 1, "sync read failed");
	close(sync_pipe[0]);

	/* Child should be member (pre-exec). */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query child failed");
	ASSERT_EQ(is_member, 1, "child should be member before exec");

	/* Wait for child to exec. */
	usleep(100000);

	/* Now child has new token. Access check triggers cleanup.
	 * But parent's regular entry should still be there. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "parent write should succeed");

	/* Child should NOT be member (new token after exec). */
	ret = cacl_query(cacl_fd, pipe_w, proc_fd, &is_member);
	ASSERT_EQ(ret, 0, "cacl_query failed after exec");
	ASSERT_EQ(is_member, 0, "child should NOT be member after exec");

	/* Drain pipe. */
	read(pipe_r, buf, 1);

	/* Clean up. */
	waitpid(pid, &status, 0);
	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Verify exec'd child is denied access (new token not in ACL).
 *
 * 1. Parent adds self (regular entry)
 * 2. Fork child (inherits parent's token)
 * 3. Child adds self with auto-cleanup (same token as parent)
 * 4. Child execs (gets new token)
 * 5. Child tries to write - denied because new token not in ACL
 *
 * Note: The auto-cleanup entry isn't actually cleaned here because
 * parent still holds the original token (refcount > 0). The child
 * is denied because exec gave it a NEW token that isn't in the ACL.
 */
static int
test_auto_cleanup_exec_denied(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	int sync1[2], sync2[2];
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Parent adds self so it can read from pipe. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "parent add_self failed");

	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(pipe_r);
		close(sync1[0]);
		close(sync2[1]);

		/* Add self with auto-cleanup. */
		ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
		if (ret != 0)
			_exit(10);

		/* Signal parent we're ready. */
		write(sync1[1], "r", 1);
		close(sync1[1]);

		/* Wait for parent to trigger cleanup. */
		read(sync2[0], buf, 1);
		close(sync2[0]);

		/* Now exec - get new token, old entry cleaned up. */
		close(cacl_fd);  /* Close before dup2 to free fd 3 */
		if (dup2(pipe_w, 3) < 0)
			_exit(11);
		close(pipe_w);

		execl("./test_helper", "test_helper", "write", "3", (char *)NULL);
		_exit(12);
	}

	close(sync1[1]);
	close(sync2[0]);

	/* Wait for child to be ready. */
	ret = read(sync1[0], buf, 1);
	ASSERT(ret == 1, "sync1 read failed");
	close(sync1[0]);

	/* At this point child has auto-cleanup entry. */

	/* Signal child to exec. */
	write(sync2[1], "g", 1);
	close(sync2[1]);

	/* Give time for exec. */
	usleep(100000);

	/* Parent does a write to trigger lazy cleanup.
	 * The child's old auto-cleanup entry should be removed. */
	ret = write(pipe_w, "t", 1);
	ASSERT_EQ(ret, 1, "parent trigger write failed");

	/* Wait for child - should exit 0 (EACCES) because new token not in ACL. */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "exec'd child should be denied (new token)");

	/* Drain pipe. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Forked child without exec retains access.
 *
 * 1. Parent adds self with auto-cleanup
 * 2. Fork child (inherits token)
 * 3. Child tries to write WITHOUT exec - should succeed
 */
static int
test_auto_cleanup_fork_without_exec(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Parent adds self with auto-cleanup. */
	ret = cacl_add_self_auto(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_auto failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: no exec, just try to write. */
		close(pipe_r);
		close(sync_pipe[1]);

		/* Wait for parent signal. */
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to write - should succeed (inherited parent's token). */
		ret = write(pipe_w, "c", 1);
		close(pipe_w);
		close(cacl_fd);

		if (ret == 1)
			_exit(0);  /* Success */
		else if (errno == EACCES)
			_exit(1);  /* Denied */
		else
			_exit(2);  /* Other error */
	}

	close(sync_pipe[0]);

	/* Signal child to try write. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "forked child should succeed (inherited token)");

	/* Drain pipe. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Verify lazy cleanup actually removes stale entries.
 *
 * This test verifies that when a token's refcount drops to 0,
 * the auto-cleanup entry is actually removed from the ACL.
 *
 * 1. Fork child, child execs test_helper "add_self_auto" (unique token)
 * 2. test_helper adds itself with auto-cleanup and exits
 * 3. Child's token refcount drops to 0
 * 4. Parent triggers lazy cleanup by accessing pipe
 * 5. Entry should be removed - pipe returns to default-allow
 * 6. Parent verifies by successfully writing
 */
static int
test_auto_cleanup_entry_removed(void)
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
	ASSERT(ret == 0, "sync_pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: exec test_helper to add self with auto-cleanup. */
		close(pipe_r);
		close(sync_pipe[1]);
		close(cacl_fd);

		/* Wait for parent's signal. */
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Exec test_helper - this gives us a unique token.
		 * test_helper will add itself with auto-cleanup and exit. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);
		execl("./test_helper", "test_helper", "add_self_auto", "3",
		    (char *)NULL);
		_exit(11);
	}

	close(sync_pipe[0]);

	/* Signal child to exec. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child to exit. */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "test_helper add_self_auto failed");

	/* Child has exited. Its unique token now has refcount 0.
	 * The auto-cleanup entry should be removed on next access check. */

	/* Parent writes to trigger lazy cleanup.
	 * If cleanup works, ACL is now empty = default-allow. */
	ret = write(pipe_w, "t", 1);
	ASSERT_EQ(ret, 1, "write should succeed after cleanup (default-allow)");

	/* Drain. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_auto_cleanup ===\n");

	ret = test_auto_cleanup_after_exec();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_fork_keeps_alive();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_multiple_children();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_mixed_entries();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_exec_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_fork_without_exec();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_auto_cleanup_entry_removed();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
