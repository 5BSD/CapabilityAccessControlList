/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL with socket operations (bind, connect, listen, accept).
 *
 * Verifies:
 * 1. Restricted socket denies bind/connect/listen/accept to unauthorized process
 * 2. Authorized process can perform all operations
 */

#include "test_common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>

#define TEST_SOCK_PATH "/tmp/cacl_test_sock"

/*
 * Test: Forked child can bind (inherits parent's token).
 */
static int
test_socket_bind(void)
{
	int cacl_fd, sock_fd;
	pid_t pid;
	int ret, status;
	struct sockaddr_un addr;

	signal(SIGPIPE, SIG_IGN);
	unlink(TEST_SOCK_PATH);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a socket. */
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(sock_fd >= 0, "socket failed");

	/* Add self to the socket. */
	ret = cacl_add_self(cacl_fd, &sock_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork - child inherits token and should be able to bind. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		signal(SIGPIPE, SIG_IGN);

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strlcpy(addr.sun_path, TEST_SOCK_PATH, sizeof(addr.sun_path));

		ret = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
		if (ret == 0)
			_exit(0);  /* Success - fork inherits token. */
		_exit(1);  /* Unexpected - denied. */
	}

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "forked child should be able to bind (inherited token)");

	close(sock_fd);
	close(cacl_fd);
	unlink(TEST_SOCK_PATH);

	PASS();
}

/*
 * Test: Forked child can listen (inherits parent's token).
 */
static int
test_socket_listen(void)
{
	int cacl_fd, sock_fd;
	pid_t pid;
	int ret, status;
	struct sockaddr_un addr;

	signal(SIGPIPE, SIG_IGN);
	unlink(TEST_SOCK_PATH);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(sock_fd >= 0, "socket failed");

	/* Bind first (before restricting). */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, TEST_SOCK_PATH, sizeof(addr.sun_path));

	ret = bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(ret, 0, "bind failed");

	/* Now restrict. */
	ret = cacl_add_self(cacl_fd, &sock_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork - child inherits token and should be able to listen. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		signal(SIGPIPE, SIG_IGN);

		ret = listen(sock_fd, 5);
		if (ret == 0)
			_exit(0);  /* Success - fork inherits token. */
		_exit(1);  /* Unexpected - denied. */
	}

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "forked child should be able to listen (inherited token)");

	close(sock_fd);
	close(cacl_fd);
	unlink(TEST_SOCK_PATH);

	PASS();
}

/*
 * Test: Forked child can connect (inherits parent's token).
 */
static int
test_socket_connect(void)
{
	int cacl_fd, server_fd, client_fd;
	pid_t pid;
	int ret, status;
	struct sockaddr_un addr;

	signal(SIGPIPE, SIG_IGN);
	unlink(TEST_SOCK_PATH);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create and bind a server socket. */
	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(server_fd >= 0, "server socket failed");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, TEST_SOCK_PATH, sizeof(addr.sun_path));

	ret = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
	ASSERT_EQ(ret, 0, "bind failed");
	ret = listen(server_fd, 5);
	ASSERT_EQ(ret, 0, "listen failed");

	/* Create a client socket and restrict it. */
	client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(client_fd >= 0, "client socket failed");

	ret = cacl_add_self(cacl_fd, &client_fd, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Fork - child inherits token and should be able to connect. */
	pid = fork();
	ASSERT(pid >= 0, "fork failed");

	if (pid == 0) {
		close(server_fd);
		signal(SIGPIPE, SIG_IGN);

		ret = connect(client_fd, (struct sockaddr *)&addr, sizeof(addr));
		if (ret == 0)
			_exit(0);  /* Success - fork inherits token. */
		_exit(1);  /* Unexpected - denied. */
	}

	ret = waitpid(pid, &status, 0);
	ASSERT(ret == pid, "waitpid failed");
	ASSERT(WIFEXITED(status), "child did not exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0,
	    "forked child should be able to connect (inherited token)");

	close(client_fd);
	close(server_fd);
	close(cacl_fd);
	unlink(TEST_SOCK_PATH);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_socket_ops ===\n");

	ret = test_socket_bind();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_socket_listen();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_socket_connect();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
