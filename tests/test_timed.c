/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_ADD_TIMED and CACL_IOC_ADD_SELF_TIMED.
 *
 * Time-based expiry entries are removed after timeout seconds
 * OR when no process holds the associated token (whichever first).
 */

#include "test_common.h"

/*
 * Test: Basic add_self_timed functionality.
 *
 * 1. Add self with 2 second timeout
 * 2. Verify access works immediately
 * 3. Wait for timeout
 * 4. Verify entry expired (default-allow since ACL empty)
 */
static int
test_add_self_timed_basic(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self with 1 second timeout. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_timed failed");

	/* Count should be 1. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1 after add_self_timed");

	/* Write should succeed. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write should succeed");

	/* Drain. */
	read(pipe_r, buf, 1);

	/* Wait for timeout (1 second + margin). */
	sleep(2);

	/* Trigger lazy cleanup by doing an operation. */
	ret = write(pipe_w, "y", 1);
	/* Should succeed - ACL is now empty = default-allow. */
	ASSERT_EQ(ret, 1, "write should succeed after timeout (default-allow)");

	/* Count should be 0 after expiry. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after timeout");
	ASSERT_EQ(count, 0, "count should be 0 after timeout expiry");

	/* Drain. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Add_timed with process descriptor.
 *
 * 1. Fork child
 * 2. Add child with 2 second timeout
 * 3. Child writes - should succeed
 * 4. Wait for timeout
 * 5. Entry should be expired
 */
static int
test_add_timed_basic(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	uint32_t count;
	int locked;
	char buf[8];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync_pipe failed");

	/* Fork child using pdfork. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		close(pipe_r);
		close(sync_pipe[1]);
		close(cacl_fd);

		/* Wait for parent signal. */
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Exec to get unique token. */
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		close(pipe_w);
		execl("./test_helper", "test_helper", "write", "3",
		    (char *)NULL);
		_exit(11);
	}

	close(sync_pipe[0]);

	/* Give child time to start. */
	usleep(50000);

	/* Signal child to exec. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child to exec. */
	usleep(100000);

	/* Add child with 1 second timeout. */
	ret = cacl_add_timed(cacl_fd, &pipe_w, 1, &proc_fd, 1, 1);
	ASSERT_EQ(ret, 0, "cacl_add_timed failed");

	/* Count should be 1. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1");

	/* Wait for child - it tried to write. */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	/* Child write should succeed (exit 1 = success). */
	ASSERT_EQ(WEXITSTATUS(status), 1, "child write should succeed");

	/* Read what child wrote. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "should read child's data");

	/* Child has exited, but entry still exists (not yet timed out). */
	/* Actually, child exit also triggers cleanup since token refcount = 0. */
	/* Let's check count - might be 0 if auto-cleanup ran. */

	/* Wait for timeout just to be sure. */
	sleep(2);

	/* Count should be 0. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after timeout");
	ASSERT_EQ(count, 0, "count should be 0 after expiry");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Timed entry expires before process exits.
 *
 * 1. Parent adds self with short timeout
 * 2. Parent waits for timeout
 * 3. Entry should be removed even though parent still holds token
 */
static int
test_timed_expires_while_alive(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self with 1 second timeout. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_timed failed");

	/* Count should be 1. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1");

	/* We're still alive, holding the token. */
	/* Wait for timeout (1 second + small margin). */
	usleep(1200000);  /* 1.2 seconds */

	/* Trigger lazy cleanup. */
	ret = write(pipe_w, "x", 1);
	/* Should succeed - default-allow. */
	ASSERT_EQ(ret, 1, "write should succeed (default-allow)");

	/* Entry should be expired. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after expiry");
	ASSERT_EQ(count, 0, "count should be 0 - entry expired even though process alive");

	/* Drain. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Process exit removes entry before timeout.
 *
 * 1. Fork child, add child with long timeout
 * 2. Child exits
 * 3. Entry should be removed immediately (auto-cleanup)
 * 4. Don't wait for timeout
 *
 * Note: Lazy cleanup only triggers on actual file operations,
 * not on count/query. We need to do a write to trigger it.
 */
static int
test_timed_exit_before_timeout(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret, status;
	uint32_t count;
	int locked;
	char buf[1];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self so we can do operations to trigger cleanup. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork child. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child: exec and exit immediately. */
		close(pipe_r);
		close(cacl_fd);
		execl("./test_helper", "test_helper", "wait", "3",
		    (char *)NULL);
		_exit(10);
	}

	/* Give child time to exec. */
	usleep(100000);

	/* Add child with 60 second timeout (long). */
	ret = cacl_add_timed(cacl_fd, &pipe_w, 1, &proc_fd, 1, 60);
	ASSERT_EQ(ret, 0, "cacl_add_timed failed");

	/* Count should be 2 (self + child). */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 2, "count should be 2");

	/* Wait for child to exit (test_helper wait with no sync_fd exits). */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit");

	/* Child exited. Trigger lazy cleanup with a write operation. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write to trigger cleanup failed");
	read(pipe_r, buf, 1);

	/* Now check count - child's entry should be cleaned up. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after child exit");
	/* Entry should be removed - auto-cleanup on process exit. */
	/* Only our entry (self) should remain. */
	ASSERT_EQ(count, 1, "count should be 1 - child auto-cleaned");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Adding same token twice updates/extends the entry.
 *
 * When the same process adds itself twice with different timeouts,
 * implementation may either update the timeout or create separate entries.
 * This test verifies the operation succeeds and basic behavior is correct.
 */
static int
test_timed_multiple_timeouts(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self with 1 second timeout. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 1);
	ASSERT_EQ(ret, 0, "first cacl_add_self_timed failed");

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1");

	/* Add self again with 1 second timeout. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 1);
	ASSERT_EQ(ret, 0, "second cacl_add_self_timed failed");

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	/* Count could be 1 (updated) or 2 (new entry). */
	ASSERT(count >= 1, "count should be at least 1");

	/* Verify we still have access. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write should succeed while entry active");
	read(pipe_r, buf, 1);

	/* Wait for expiry (1 second + margin). */
	usleep(1500000);  /* 1.5 seconds */

	/* Trigger lazy cleanup. */
	ret = write(pipe_w, "y", 1);
	/* Should succeed - default-allow after cleanup. */
	ASSERT_EQ(ret, 1, "write should succeed (default-allow after expiry)");
	read(pipe_r, buf, 1);

	/* Verify entries expired. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after expiry");
	ASSERT_EQ(count, 0, "count should be 0 after all expired");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Timed entry with zero timeout.
 *
 * Zero timeout should still work (immediate or very short).
 */
static int
test_timed_zero_timeout(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self with 0 second timeout. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 0);
	/* Could fail or succeed depending on implementation. */
	if (ret != 0) {
		/* Zero timeout rejected - that's acceptable. */
		close(pipe_r);
		close(pipe_w);
		close(cacl_fd);
		PASS();
	}

	/* If it succeeded, entry should expire immediately or very soon. */
	usleep(100000);  /* 100ms */

	/* Trigger cleanup. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write should succeed");
	read(pipe_r, buf, 1);

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 0, "count should be 0 after zero timeout");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Timed entry on locked ACL.
 *
 * Adding timed entry to locked ACL is allowed - lock only affects
 * access checks, not ACL modifications. The added process can access
 * the descriptor even though the ACL is locked.
 */
static int
test_timed_on_locked(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Lock the pipe. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Verify locked state. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(locked, 1, "should be locked");
	ASSERT_EQ(count, 0, "count should be 0");

	/* Add timed entry - should succeed even on locked ACL. */
	ret = cacl_add_self_timed(cacl_fd, &pipe_w, 1, 2);
	ASSERT_EQ(ret, 0, "cacl_add_self_timed should succeed on locked ACL");

	/* Now we should have access. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write should succeed after adding self");
	read(pipe_r, buf, 1);

	/* Count should be 1, still locked. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(locked, 1, "should still be locked");
	ASSERT_EQ(count, 1, "count should be 1");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Timed entry on multiple descriptors.
 *
 * Add timed entry to multiple pipes at once.
 */
static int
test_timed_multiple_fds(void)
{
	int cacl_fd;
	int pipe1_r, pipe1_w, pipe2_r, pipe2_w;
	int caps[2];
	int ret;
	uint32_t count;
	int locked;
	char buf[1];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe1_r, &pipe1_w);
	ASSERT(ret == 0, "create_pipe1 failed");

	ret = create_pipe(&pipe2_r, &pipe2_w);
	ASSERT(ret == 0, "create_pipe2 failed");

	caps[0] = pipe1_w;
	caps[1] = pipe2_w;

	/* Add self with 1 second timeout to both pipes. */
	ret = cacl_add_self_timed(cacl_fd, caps, 2, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self_timed failed");

	/* Both should have count 1. */
	ret = cacl_count(cacl_fd, pipe1_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count pipe1 failed");
	ASSERT_EQ(count, 1, "pipe1 count should be 1");

	ret = cacl_count(cacl_fd, pipe2_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count pipe2 failed");
	ASSERT_EQ(count, 1, "pipe2 count should be 1");

	/* Wait for timeout. */
	usleep(1500000);  /* 1.5 seconds */

	/* Trigger cleanup on both. */
	ret = write(pipe1_w, "x", 1);
	ASSERT_EQ(ret, 1, "pipe1 write should succeed");
	ret = write(pipe2_w, "y", 1);
	ASSERT_EQ(ret, 1, "pipe2 write should succeed");

	read(pipe1_r, buf, 1);
	read(pipe2_r, buf, 1);

	/* Both should be 0. */
	ret = cacl_count(cacl_fd, pipe1_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count pipe1 failed after expiry");
	ASSERT_EQ(count, 0, "pipe1 count should be 0");

	ret = cacl_count(cacl_fd, pipe2_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count pipe2 failed after expiry");
	ASSERT_EQ(count, 0, "pipe2 count should be 0");

	close(pipe1_r);
	close(pipe1_w);
	close(pipe2_r);
	close(pipe2_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_timed ===\n");

	ret = test_add_self_timed_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_timed_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_expires_while_alive();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_exit_before_timeout();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_multiple_timeouts();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_zero_timeout();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_on_locked();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_timed_multiple_fds();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
