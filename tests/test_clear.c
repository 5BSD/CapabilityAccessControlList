/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_CLEAR ioctl.
 *
 * Verifies:
 * 1. Clearing an access list removes all entries
 * 2. After clear, all processes can access (default-allow)
 */

#include "test_common.h"
#include <signal.h>

/*
 * Test that clearing ACL restores default-allow behavior.
 *
 * 1. Add self to pipe ACL (restricts access)
 * 2. Verify exec'd child is denied (not in ACL)
 * 3. Clear ACL
 * 4. Verify new child can now write (default-allow)
 */
static int
test_clear_restores_default_allow(void)
{
	int cacl_fd, pipe_r, pipe_w;
	pid_t pid1, pid2;
	int ret, status;
	int sync1[2], sync2[2];
	char buf[8];

	signal(SIGPIPE, SIG_IGN);

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	ret = pipe(sync1);
	ASSERT(ret == 0, "sync1 pipe failed");
	ret = pipe(sync2);
	ASSERT(ret == 0, "sync2 pipe failed");

	/* Add self to the pipe (restricts access, but parent can still use). */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Child 1: Should be denied (not in ACL after exec). */
	pid1 = fork();
	ASSERT(pid1 >= 0, "fork1 failed");
	if (pid1 == 0) {
		close(pipe_r);
		close(sync1[1]);
		close(sync2[0]);
		close(sync2[1]);
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		if (dup2(sync1[0], 4) < 0)
			_exit(11);
		close(pipe_w);
		close(sync1[0]);
		execl("./test_helper", "test_helper", "write", "3", "4",
		    (char *)NULL);
		_exit(12);
	}
	close(sync1[0]);

	/* Give child time to exec. */
	usleep(100000);

	/* Signal child1 to try write - should fail (not in ACL). */
	write(sync1[1], "g", 1);
	close(sync1[1]);

	waitpid(pid1, &status, 0);
	ASSERT(WIFEXITED(status), "child1 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child1 should get EACCES");

	/* Clear the access list - now everyone can access. */
	ret = cacl_clear(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_clear failed");

	/* Child 2: Should succeed (ACL cleared, default-allow). */
	pid2 = fork();
	ASSERT(pid2 >= 0, "fork2 failed");
	if (pid2 == 0) {
		close(pipe_r);
		close(sync2[1]);
		if (dup2(pipe_w, 3) < 0)
			_exit(10);
		if (dup2(sync2[0], 4) < 0)
			_exit(11);
		close(pipe_w);
		close(sync2[0]);
		execl("./test_helper", "test_helper", "write", "3", "4",
		    (char *)NULL);
		_exit(12);
	}
	close(sync2[0]);

	/* Give child time to exec. */
	usleep(100000);

	/* Signal child2 to try write - should succeed. */
	write(sync2[1], "g", 1);
	close(sync2[1]);

	waitpid(pid2, &status, 0);
	ASSERT(WIFEXITED(status), "child2 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 1, "child2 write should succeed after clear");

	/* Verify we got data from child2. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "didn't receive child2's write");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_clear ===\n");

	ret = test_clear_restores_default_allow();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
