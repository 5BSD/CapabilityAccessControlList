/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_REMOVE_SELF and CACL_IOC_COUNT.
 */

#include "test_common.h"

/*
 * Test: Basic remove_self functionality.
 *
 * 1. Add self to ACL
 * 2. Verify count is 1
 * 3. Remove self from ACL
 * 4. Verify count is 0
 */
static int
test_remove_self_basic(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Count should be 1. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1 after add_self");
	ASSERT_EQ(locked, 0, "should not be locked");

	/* Remove self. */
	ret = cacl_remove_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_remove_self failed");

	/* Count should be 0. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after remove");
	ASSERT_EQ(count, 0, "count should be 0 after remove_self");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Remove self restores default-allow.
 *
 * 1. Add self (creates ACL)
 * 2. Fork child (inherits token)
 * 3. Remove self
 * 4. ACL is now empty = default-allow
 * 5. Child (same token, but removed) should still be allowed
 */
static int
test_remove_self_default_allow(void)
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

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "sync pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Child: wait, then try to write. */
		close(pipe_r);
		close(sync_pipe[1]);

		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to write - should succeed (default-allow). */
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

	/* Remove self - ACL becomes empty = default-allow. */
	ret = cacl_remove_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_remove_self failed");

	/* Signal child to try write. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	waitpid(pid, &status, 0);
	ASSERT(WIFEXITED(status), "child didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "child should succeed (default-allow after remove_self)");

	/* Drain. */
	read(pipe_r, buf, 1);

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Count reflects locked state.
 */
static int
test_count_locked(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	uint32_t count;
	int locked;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Initially no ACL. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 0, "count should be 0 initially");
	ASSERT_EQ(locked, 0, "should not be locked initially");

	/* Lock the pipe. */
	ret = cacl_lock(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_lock failed");

	/* Count should be 0, locked should be 1. */
	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed after lock");
	ASSERT_EQ(count, 0, "count should be 0 after lock");
	ASSERT_EQ(locked, 1, "should be locked");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Count with multiple entries.
 */
static int
test_count_multiple(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd;
	pid_t pid;
	int ret;
	uint32_t count;
	int locked;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1");

	/* Fork a child and add it. */
	pid = pdfork(&proc_fd, 0);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child: just wait and exit. */
		sleep(1);
		_exit(0);
	}

	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add failed");

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 2, "count should be 2");

	/* Remove child. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_remove failed");

	ret = cacl_count(cacl_fd, pipe_w, &count, &locked);
	ASSERT_EQ(ret, 0, "cacl_count failed");
	ASSERT_EQ(count, 1, "count should be 1 after remove");

	/* Clean up. */
	close(proc_fd);
	waitpid(pid, NULL, 0);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Remove self when not in ACL is a no-op.
 */
static int
test_remove_self_not_member(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Don't add self - just try to remove. */
	ret = cacl_remove_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_remove_self should succeed (no-op)");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_remove_self ===\n");

	ret = test_remove_self_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_remove_self_default_allow();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_count_locked();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_count_multiple();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_remove_self_not_member();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
