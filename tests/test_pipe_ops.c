/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test pipe operations beyond read/write.
 *
 * Verifies:
 * 1. poll() on pipe is controlled by CACL
 * 2. ioctl() on pipe is controlled by CACL
 * 3. fstat() on pipe is controlled by CACL
 */

#include "test_common.h"
#include <poll.h>
#include <sys/filio.h>
#include <sys/stat.h>

static int
test_pipe_poll_allowed(void)
{
	int cacl_fd, pipe_r, pipe_w;
	struct pollfd pfd;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Write some data so pipe is readable. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write failed");

	/* Poll should succeed since we're on the ACL. */
	pfd.fd = pipe_r;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ret = poll(&pfd, 1, 100);
	ASSERT(ret == 1, "poll should return 1");
	ASSERT(pfd.revents & POLLIN, "pipe should be readable");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Forked child inherits token and CAN poll (same token as parent).
 * This verifies fork inheritance works correctly.
 */
static int
test_pipe_poll_fork_allowed(void)
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

	/* Add self - child will inherit this token. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Write data so pipe is readable. */
	ret = write(pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write failed");

	pid = fork_child(&proc_fd);
	ASSERT(pid >= 0, "pdfork failed");

	if (pid == 0) {
		/* Child inherits parent's token - should have access. */
		struct pollfd pfd;
		close(cacl_fd);
		close(pipe_w);
		close(sync_pipe[1]);

		read(sync_pipe[0], buf, 1);
		close(sync_pipe[0]);

		/* Poll should succeed (inherited token). */
		pfd.fd = pipe_r;
		pfd.events = POLLIN;
		ret = poll(&pfd, 1, 100);
		if (ret == 1 && (pfd.revents & POLLIN))
			_exit(0);	/* Success - access allowed. */
		_exit(1);
	}

	close(sync_pipe[0]);
	write(sync_pipe[1], "g", 1);
	close(sync_pipe[1]);

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "forked child should have access");

	close(proc_fd);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

static int
test_pipe_ioctl(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int nbytes;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Write some data. */
	ret = write(pipe_w, "test", 4);
	ASSERT_EQ(ret, 4, "write failed");

	/* FIONREAD ioctl should succeed. */
	ret = ioctl(pipe_r, FIONREAD, &nbytes);
	ASSERT_EQ(ret, 0, "ioctl FIONREAD failed");
	ASSERT_EQ(nbytes, 4, "wrong byte count");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

static int
test_pipe_fstat(void)
{
	int cacl_fd, pipe_r, pipe_w;
	struct stat sb;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self to read end. */
	ret = cacl_add_self(cacl_fd, &pipe_r, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* fstat should succeed. */
	ret = fstat(pipe_r, &sb);
	ASSERT_EQ(ret, 0, "fstat failed");
	ASSERT(S_ISFIFO(sb.st_mode), "pipe should be FIFO");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_pipe_ops ===\n");

	ret = test_pipe_poll_allowed();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_pipe_poll_fork_allowed();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_pipe_ioctl();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_pipe_fstat();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
