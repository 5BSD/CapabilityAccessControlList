/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test multiple fd operations.
 *
 * Verifies:
 * 1. Multiple fds can be added to ACL in single call
 *
 * NOTE: Multiple PROCESS tests are in test_add.c (test_add_multiple_processes).
 * Denial tests are in test_exec.c and test_unit.c (test_denial_works).
 */

#include "test_common.h"

/*
 * Test: verify adding multiple fds to same process works in single call.
 */
static int
test_multi_fd(void)
{
	int cacl_fd;
	int pipe1[2], pipe2[2];
	int ret;
	char buf[8];

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = pipe(pipe1);
	ASSERT(ret == 0, "pipe1 failed");

	ret = pipe(pipe2);
	ASSERT(ret == 0, "pipe2 failed");

	/* Add self to both pipes at once. */
	int fds[2] = { pipe1[1], pipe2[1] };
	ret = cacl_add_self(cacl_fd, fds, 2);
	ASSERT_EQ(ret, 0, "cacl_add_self multiple fds failed");

	/* Verify we can write to both. */
	ret = write(pipe1[1], "a", 1);
	ASSERT_EQ(ret, 1, "write to pipe1 failed");

	ret = write(pipe2[1], "b", 1);
	ASSERT_EQ(ret, 1, "write to pipe2 failed");

	/* Verify data. */
	ret = read(pipe1[0], buf, 1);
	ASSERT_EQ(ret, 1, "read from pipe1 failed");
	ASSERT_EQ(buf[0], 'a', "wrong data from pipe1");

	ret = read(pipe2[0], buf, 1);
	ASSERT_EQ(ret, 1, "read from pipe2 failed");
	ASSERT_EQ(buf[0], 'b', "wrong data from pipe2");

	close(pipe1[0]);
	close(pipe1[1]);
	close(pipe2[0]);
	close(pipe2[1]);
	close(cacl_fd);

	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_multi ===\n");

	ret = test_multi_fd();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
