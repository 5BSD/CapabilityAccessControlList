/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test CACL_IOC_REMOVE ioctl.
 *
 * Verifies:
 * 1. Removing a process from the access list denies future access
 */

#include "test_common.h"
#include <signal.h>

/*
 * Test removing a process from access list.
 *
 * 1. Create pipe, add child to ACL
 * 2. Child writes successfully
 * 3. Remove child from ACL
 * 4. Child's second write fails with EACCES
 */
static int
test_remove_denies_access(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int proc_fd1, proc_fd2;
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

	/*
	 * Use two separate children for before/after removal test.
	 * Each child execs test_helper to get a unique token.
	 */

	/* Child 1: Will be in ACL, write should succeed. */
	pid1 = pdfork(&proc_fd1, 0);
	ASSERT(pid1 >= 0, "pdfork1 failed");
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

	/* Child 2: Will be removed from ACL, write should fail. */
	pid2 = pdfork(&proc_fd2, 0);
	ASSERT(pid2 >= 0, "pdfork2 failed");
	if (pid2 == 0) {
		close(pipe_r);
		close(sync1[1]);
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

	/* Give children time to exec. */
	usleep(100000);

	/* Add self to pipe ACL (needed to read - pipes share one ACL). */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT_EQ(ret, 0, "cacl_add_self failed");

	/* Add both children to ACL initially. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd1, 1);
	ASSERT_EQ(ret, 0, "cacl_add child1 failed");
	ret = cacl_add(cacl_fd, &pipe_w, 1, &proc_fd2, 1);
	ASSERT_EQ(ret, 0, "cacl_add child2 failed");

	/* Remove child2 from ACL. */
	ret = cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd2, 1);
	ASSERT_EQ(ret, 0, "cacl_remove failed");

	/* Signal both children to try their writes. */
	write(sync1[1], "g", 1);
	write(sync2[1], "g", 1);
	close(sync1[1]);
	close(sync2[1]);

	/* Child1 should succeed (exit 1 = write worked). */
	waitpid(pid1, &status, 0);
	ASSERT(WIFEXITED(status), "child1 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 1, "child1 write should succeed");

	/* Child2 should fail (exit 0 = EACCES). */
	waitpid(pid2, &status, 0);
	ASSERT(WIFEXITED(status), "child2 didn't exit normally");
	ASSERT_EQ(WEXITSTATUS(status), 0, "child2 should get EACCES after removal");

	/* Verify we got data from child1. */
	ret = read(pipe_r, buf, 1);
	ASSERT_EQ(ret, 1, "should have received data from child1");

	close(proc_fd1);
	close(proc_fd2);
	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_remove ===\n");

	ret = test_remove_denies_access();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
