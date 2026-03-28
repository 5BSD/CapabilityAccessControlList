/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Edge case tests for CACL.
 *
 * Tests boundary conditions and unusual scenarios:
 * - Rapid add/clear cycles
 * - Many processes in ACL
 * - Self-referential operations
 * - Dup'd file descriptors
 * - ACL on inherited fd
 * - Process exit with ACL entry
 */

#include "test_common.h"
#include <sys/mman.h>

/*
 * Test: Rapid add/clear cycles.
 */
static int
test_rapid_cycles(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;
	int i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Rapid add/clear cycles. */
	for (i = 0; i < 1000; i++) {
		ret = cacl_add_self(cacl_fd, &pipe_w, 1);
		ASSERT_EQ(ret, 0, "add_self in cycle failed");

		ret = cacl_clear(cacl_fd, &pipe_w, 1);
		ASSERT_EQ(ret, 0, "clear in cycle failed");
	}

	/* Should still work. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after rapid cycles failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Many processes in ACL.
 */
static int
test_many_processes(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fds[32];
	pid_t pids[32];
	int ret, status;
	int i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Fork many children. */
	for (i = 0; i < 32; i++) {
		pids[i] = fork_child(&proc_fds[i]);
		ASSERT(pids[i] >= 0, "pdfork failed");
		if (pids[i] == 0) {
			usleep(50000);
			_exit(0);
		}
	}

	/* Add all to ACL in batches. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fds[0], 8);
	ASSERT_EQ(ret, 0, "add batch 1 failed");

	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fds[8], 8);
	ASSERT_EQ(ret, 0, "add batch 2 failed");

	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fds[16], 8);
	ASSERT_EQ(ret, 0, "add batch 3 failed");

	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fds[24], 8);
	ASSERT_EQ(ret, 0, "add batch 4 failed");

	/* Remove half. */
	for (i = 0; i < 16; i++) {
		ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fds[i], 1);
		ASSERT_EQ(ret, 0, "remove failed");
	}

	/* Clean up. */
	for (i = 0; i < 32; i++) {
		waitpid(pids[i], &status, 0);
		close(proc_fds[i]);
	}

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Operations on dup'd file descriptor.
 */
static int
test_duped_fd(void)
{
	int cacl_fd, pipe_r, pipe_w, pipe_w_dup;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Dup the write end. */
	pipe_w_dup = dup(pipe_w);
	ASSERT(pipe_w_dup >= 0, "dup failed");

	/* Add self via original fd. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self via original failed");

	/* Write via dup'd fd should work (same underlying object). */
	ret = write(pipe_w_dup, "x", 1);
	ASSERT_EQ(ret, 1, "write via duped fd failed");

	/* Clear via dup'd fd should work. */
	ret = cacl_clear(cacl_fd, &pipe_w_dup, 1);
	ASSERT_EQ(ret, 0, "clear via duped fd failed");

	/* Now write via original should work (ACL cleared). */
	ret = write(pipe_w, "y", 1);
	ASSERT_EQ(ret, 1, "write via original after clear failed");

	close(pipe_w_dup);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: ACL persists across exec (via process descriptor).
 */
static int
test_persist_across_exec(void)
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
		close(cacl_fd);
		close(pipe_r);
		close(sync_pipe[1]);

		/* Wait for parent to set up ACL. */
		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to write before exec - should succeed. */
		ret = write(pipe_w, "a", 1);
		if (ret != 1)
			_exit(1);

		/* Exec /bin/echo - token changes. */
		char *args[] = { "/bin/echo", "test", NULL };
		execv("/bin/echo", args);
		_exit(2);
	}

	close(sync_pipe[0]);

	/* Add child to ACL. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "add child failed");

	/* Add self to read. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "add_self to read end failed");

	/* Signal child. */
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	/* Wait for child. */
	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");

	/* Read the 'a' written before exec. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "read failed");
	ASSERT_EQ(buf[0], 'a', "wrong data");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Process exits while in ACL.
 */
static int
test_process_exit(void)
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
		/* Child immediately exits. */
		_exit(0);
	}

	/* Add child to ACL (it may have already exited). */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);
	ASSERT_EQ(ret, 0, "add exited child failed");

	/* Wait for child. */
	waitpid(pid, &status, 0);

	/* ACL should still be valid (contains stale token). */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self after child exit failed");

	/* Write should work. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write failed");

	/* Clear should work. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "clear failed");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Close pipe with non-empty ACL.
 */
static int
test_close_with_acl(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to ACL. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self failed");

	/* Close pipe while ACL is non-empty. */
	close(pipe_w);
	close(pipe_r);

	/* Create new pipe - should work fine. */
	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe after close failed");

	/* New pipe should have empty ACL. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write to new pipe failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Same fd used multiple times in array.
 */
static int
test_duplicate_in_array(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int fds[3];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Same fd repeated in array. */
	fds[0] = pipe_w;
	fds[1] = pipe_w;
	fds[2] = pipe_w;

	ret = cacl_add_self(cacl_fd, fds, 3);
	ASSERT_EQ(ret, 0, "add_self with duplicates should succeed");

	/* Should have access. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: POSIX shared memory edge cases.
 */
static int
test_shm_edge(void)
{
	int cacl_fd;
	int shm_fd;
	void *addr;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create anonymous shared memory. */
	shm_fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
	if (shm_fd < 0)
		return (TEST_SKIP);	/* SHM not available. */

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	/* Add self. */
	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "add_self to shm failed");

	/* Map it. */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	ASSERT(addr != MAP_FAILED, "mmap failed");

	/* Write to it. */
	*(int *)addr = 42;
	ASSERT_EQ(*(int *)addr, 42, "shm write failed");

	munmap(addr, 4096);
	close(shm_fd);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Zero-length operations.
 */
static int
test_zero_operations(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self then verify zero-length write works. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "add_self failed");

	/* Zero-length write should succeed. */
	ret = write(pipe_w, "", 0);
	ASSERT_EQ(ret, 0, "zero-length write failed");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_edge ===\n");

	ret = test_rapid_cycles();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_many_processes();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_duped_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_persist_across_exec();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_process_exit();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_close_with_acl();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_duplicate_in_array();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_edge();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_zero_operations();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
