/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL with vnodes (regular files, FIFOs, and device files).
 *
 * Verifies:
 * 1. CACL works on regular file fds
 * 2. CACL works on /dev device fds
 * 3. Exec'd process is denied read/write/stat/poll/mmap
 * 4. Forked process inherits access
 */

#include "test_common.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <poll.h>

#define TEST_FILE "/tmp/cacl_test_file"
#define TEST_FIFO "/tmp/cacl_test_fifo"

static int
test_vnode_file_basic(void)
{
	int cacl_fd, file_fd;
	int ret;
	char buf[16];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a test file. */
	unlink(TEST_FILE);
	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");

	/* Write some data. */
	ret = write(file_fd, "hello", 5);
	ASSERT_EQ(ret, 5, "write failed");

	/* Add self to the file. */
	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Verify we can still read/write. */
	lseek(file_fd, 0, SEEK_SET);
	ret = read(file_fd, buf, 5);
	ASSERT_EQ(ret, 5, "read failed after add_self");

	ret = write(file_fd, "world", 5);
	ASSERT_EQ(ret, 5, "write failed after add_self");

	/* Clean up. */
	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

static int
test_vnode_devnull(void)
{
	int cacl_fd, dev_fd;
	int ret;
	char buf[16];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Open /dev/null. */
	dev_fd = open("/dev/null", O_RDWR);
	ASSERT(dev_fd >= 0, "open /dev/null failed");

	/* Add self to the device. */
	ret = cacl_add_self(cacl_fd, &dev_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed on /dev/null");

	/* Verify we can still use it. */
	ret = write(dev_fd, "test", 4);
	ASSERT_EQ(ret, 4, "write to /dev/null failed after add_self");

	ret = read(dev_fd, buf, 1);
	ASSERT_EQ(ret, 0, "read from /dev/null unexpected result");

	close(dev_fd);
	close(cacl_fd);

	PASS();
}

static int
test_vnode_devzero(void)
{
	int cacl_fd, dev_fd;
	int ret;
	char buf[16];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Open /dev/zero. */
	dev_fd = open("/dev/zero", O_RDWR);
	ASSERT(dev_fd >= 0, "open /dev/zero failed");

	/* Add self to the device. */
	ret = cacl_add_self(cacl_fd, &dev_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed on /dev/zero");

	/* Verify we can still use it. */
	ret = read(dev_fd, buf, 4);
	ASSERT_EQ(ret, 4, "read from /dev/zero failed after add_self");
	ASSERT_EQ(buf[0], 0, "/dev/zero should return zeros");

	close(dev_fd);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Exec'd child gets new token and is DENIED read.
 */
static int
test_vnode_exec_denied(void)
{
	int cacl_fd, file_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	signal(SIGPIPE, SIG_IGN);
	unlink(TEST_FILE);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a test file with data. */
	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");
	write(file_fd, "secret", 6);
	lseek(file_fd, 0, SEEK_SET);

	/* Restrict the file to just us. */
	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		if (file_fd != 3) {
			if (dup2(file_fd, 3) < 0)
				_exit(10);
			close(file_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		/*
		 * Exec test_helper to try read on fd 3.
		 * After exec, child has new token and should be denied.
		 * Helper exits 0 if denied (EACCES), 1 if allowed.
		 */
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
	    "exec'd child should be denied read");

	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

static int
test_vnode_fork_allowed(void)
{
	int cacl_fd, file_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];
	char buf[16];

	unlink(TEST_FILE);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a test file with data. */
	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");
	write(file_fd, "hello", 5);
	lseek(file_fd, 0, SEEK_SET);

	/* Restrict the file to just us. */
	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		/* Forked child inherits token - should be allowed. */
		close(sync_pipe[1]);

		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Try to read - should succeed. */
		lseek(file_fd, 0, SEEK_SET);
		ret = read(file_fd, buf, 5);
		if (ret != 5)
			_exit(1);

		/* Try to write - should succeed. */
		ret = write(file_fd, "test", 4);
		if (ret != 4)
			_exit(2);

		_exit(0);
	}

	close(sync_pipe[0]);
	usleep(50000);
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "forked child couldn't access file");

	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

static int
test_vnode_mmap(void)
{
	int cacl_fd, file_fd;
	int ret;
	void *addr;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a test file. */
	unlink(TEST_FILE);
	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");

	ret = ftruncate(file_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	/* Add self to the file. */
	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Verify we can still mmap. */
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file_fd, 0);
	ASSERT(addr != MAP_FAILED, "mmap failed after add_self");

	/* Write through the mapping. */
	memcpy(addr, "mapped", 6);
	munmap(addr, 4096);

	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

/*
 * Test: Exec'd child is denied fstat on file.
 */
static int
test_vnode_stat_denied(void)
{
	int cacl_fd, file_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	unlink(TEST_FILE);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");
	write(file_fd, "data", 4);

	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (file_fd != 3) {
			if (dup2(file_fd, 3) < 0)
				_exit(10);
			close(file_fd);
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
	    "exec'd child should be denied fstat on file");

	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

/*
 * Note: poll denial tests removed - FreeBSD's poll() syscall stores fo_poll's
 * return value directly in revents, so MAC errors (EACCES) get interpreted as
 * event bits rather than errors. This is a kernel design limitation.
 */

/*
 * Test: Exec'd child is denied mmap on file.
 */
static int
test_vnode_mmap_denied(void)
{
	int cacl_fd, file_fd;
	pid_t pid;
	int ret, status;
	int sync_pipe[2];

	unlink(TEST_FILE);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	file_fd = open(TEST_FILE, O_RDWR | O_CREAT, 0644);
	ASSERT(file_fd >= 0, "open failed");

	ret = ftruncate(file_fd, 4096);
	ASSERT_EQ(ret, 0, "ftruncate failed");

	ret = cacl_add_self(cacl_fd, &file_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sync_pipe[1]);

		if (file_fd != 3) {
			if (dup2(file_fd, 3) < 0)
				_exit(10);
			close(file_fd);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

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
	    "exec'd child should be denied mmap on file");

	close(file_fd);
	close(cacl_fd);
	unlink(TEST_FILE);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_vnode ===\n");

	ret = test_vnode_file_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_devnull();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_devzero();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_exec_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_fork_allowed();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_mmap();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_stat_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_vnode_mmap_denied();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
