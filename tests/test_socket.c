/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL with sockets (socketpair).
 *
 * Verifies:
 * 1. CACL works on sockets, not just pipes
 * 2. Exec'd process is denied send/recv/stat/poll
 */

#include "test_common.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>

static int
test_socket_basic(void)
{
	int cacl_fd;
	int sv[2];
	int ret;
	char buf[8];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a socket pair. */
	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ASSERT(ret == 0, "socketpair failed");

	/* Add self to sv[0]. */
	ret = cacl_add_self(cacl_fd, &sv[0], 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Verify we can still use the socket. */
	buf[0] = 'x';
	ret = write(sv[0], buf, 1);
	ASSERT_EQ(ret, 1, "write to socket failed after add_self");

	ret = read(sv[1], buf, 1);
	ASSERT_EQ(ret, 1, "read from socket failed");
	ASSERT_EQ(buf[0], 'x', "wrong data");

	close(sv[0]);
	close(sv[1]);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Exec'd child gets new token and is DENIED write.
 */
static int
test_socket_exec_denied(void)
{
	int cacl_fd;
	int sv[2];
	int sync_pipe[2];
	pid_t pid;
	int ret, status;

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ASSERT(ret == 0, "socketpair failed");

	ret = cacl_add_self(cacl_fd, &sv[0], 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sv[1]);
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		if (sv[0] != 3) {
			if (dup2(sv[0], 3) < 0)
				_exit(10);
			close(sv[0]);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		/*
		 * Exec test_helper to try write on fd 3.
		 * After exec, child has new token and should be denied.
		 */
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
	    "exec'd child should be denied write to socket");

	close(sv[0]);
	close(sv[1]);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Exec'd child is denied recv.
 */
static int
test_socket_recv_denied(void)
{
	int cacl_fd;
	int sv[2];
	int sync_pipe[2];
	pid_t pid;
	int ret, status;

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ASSERT(ret == 0, "socketpair failed");

	ret = cacl_add_self(cacl_fd, &sv[0], 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sv[1]);
		close(sync_pipe[1]);
		signal(SIGPIPE, SIG_IGN);

		if (sv[0] != 3) {
			if (dup2(sv[0], 3) < 0)
				_exit(10);
			close(sv[0]);
		}
		if (sync_pipe[0] != 4) {
			if (dup2(sync_pipe[0], 4) < 0)
				_exit(11);
			close(sync_pipe[0]);
		}

		execl("./test_helper", "test_helper", "recv", "3", "4",
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
	    "exec'd child should be denied recv on socket");

	close(sv[0]);
	close(sv[1]);
	close(cacl_fd);

	PASS();
}

/*
 * Test: Exec'd child is denied fstat.
 */
static int
test_socket_stat_denied(void)
{
	int cacl_fd;
	int sv[2];
	int sync_pipe[2];
	pid_t pid;
	int ret, status;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ASSERT(ret == 0, "socketpair failed");

	ret = cacl_add_self(cacl_fd, &sv[0], 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	ret = pipe(sync_pipe);
	ASSERT(ret == 0, "pipe failed");

	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(sv[1]);
		close(sync_pipe[1]);

		if (sv[0] != 3) {
			if (dup2(sv[0], 3) < 0)
				_exit(10);
			close(sv[0]);
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
	    "exec'd child should be denied fstat on socket");

	close(sv[0]);
	close(sv[1]);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_socket ===\n");

	ret = test_socket_basic();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_socket_exec_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_socket_recv_denied();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_socket_stat_denied();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
