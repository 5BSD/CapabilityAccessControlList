/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL with POSIX shared memory.
 *
 * Verifies:
 * 1. CACL works on shm_open() fds
 * 2. Exec'd process is denied mmap/read/write/stat/truncate
 */

#include "test_common.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#define TEST_SHM_NAME "/cacl_test_shm"

static int
test_shm_basic(void)
{
	int cacl_fd, shm_fd;
	int ret;
	void *addr;

	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create shared memory. */
	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	/* Add self to the shm. */
	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Verify we can still mmap. */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	ASSERT(addr != MAP_FAILED, "mmap failed after add_self");
	munmap(addr, 4096);

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Forked child inherits token and CAN mmap.
 */
static int
test_shm_fork_allowed(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	void *addr;
	int sync_pipe[2];
	char buf[1];

	signal(SIGPIPE, SIG_IGN);
	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	/* Fork - child inherits token and should be able to mmap. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to mmap - should succeed (inherited token). */
		addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
		    shm_fd, 0);
		if (addr != MAP_FAILED) {
			munmap(addr, 4096);
			_exit(0);  /* Success - fork inherits token. */
		}
		_exit(1);  /* Unexpected - denied. */
	}

	close(sync_pipe[0]);
	usleep(50000);
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "forked child should be able to mmap (inherited token)");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Exec'd child gets new token and is DENIED mmap.
 */
static int
test_shm_exec_denied(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	signal(SIGPIPE, SIG_IGN);
	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		if (shm_fd != 3) {
			if (dup2(shm_fd, 3) < 0)
				_exit(10);
			close(shm_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		/*
		 * Exec test_helper to try mmap on fd 3.
		 * After exec, child has new token and should be denied.
		 * Helper exits 0 if denied (EACCES), 1 if allowed.
		 */
		execl("./test_helper", "test_helper", "mmap", "3", "4",
		    (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);
	usleep(100000);

	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied mmap");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Exec'd child is denied fstat on shm.
 */
static int
test_shm_stat_denied(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (shm_fd != 3) {
			if (dup2(shm_fd, 3) < 0)
				_exit(10);
			close(shm_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		execl("./test_helper", "test_helper", "fstat", "3", "4",
		    (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);
	usleep(100000);

	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied fstat on shm");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Exec'd child is denied ftruncate on shm.
 */
static int
test_shm_truncate_denied(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (shm_fd != 3) {
			if (dup2(shm_fd, 3) < 0)
				_exit(10);
			close(shm_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		execl("./test_helper", "test_helper", "ftruncate", "3", "4",
		    (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);
	usleep(100000);

	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied ftruncate on shm");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Exec'd child is denied read on shm.
 */
static int
test_shm_read_denied(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (shm_fd != 3) {
			if (dup2(shm_fd, 3) < 0)
				_exit(10);
			close(shm_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		execl("./test_helper", "test_helper", "read", "3", "4",
		    (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);
	usleep(100000);

	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied read on shm");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

/*
 * Test: Exec'd child is denied write on shm.
 */
static int
test_shm_write_denied(void)
{
	int cacl_fd, shm_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	shm_unlink(TEST_SHM_NAME);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	shm_fd = shm_open(TEST_SHM_NAME, O_RDWR | O_CREAT, 0644);
	ASSERT(shm_fd >= 0, "shm_open failed");

	ret = ftruncate(shm_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &shm_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (shm_fd != 3) {
			if (dup2(shm_fd, 3) < 0)
				_exit(10);
			close(shm_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		execl("./test_helper", "test_helper", "write", "3", "4",
		    (char *)NULL);
		_exit(12);
	}

	close(sync_pipe[0]);
	usleep(100000);

	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "exec'd child should be denied write on shm");

	close(shm_fd);
	close(cacl_fd);
	shm_unlink(TEST_SHM_NAME);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_shm ===\n");

	ret = test_shm_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_fork_allowed();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_exec_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_stat_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_truncate_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_read_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_shm_write_denied();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
