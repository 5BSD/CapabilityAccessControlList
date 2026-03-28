/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * IOCTL interface tests.
 *
 * Tests ioctl edge cases:
 * - Invalid ioctl command
 * - NULL/invalid pointers
 * - Partial success scenarios
 * - Mixed valid/invalid fds
 * - Multiple fds in single call
 */

#include "test_common.h"
#include <sys/socket.h>
#include <sys/event.h>

/*
 * Test: Invalid ioctl command returns ENOTTY.
 */
static int
test_invalid_command(void)
{
	int cacl_fd;
	int ret;
	int dummy = 0;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Use an invalid ioctl command. */
	ret = ioctl(cacl_fd, _IO('Z', 99), &dummy);
	ASSERT(ret != 0, "invalid ioctl should fail");
	ASSERT_EQ(errno, ENOTTY, "expected ENOTTY for invalid command");

	close(cacl_fd);
	PASS();
}

/*
 * Test: Empty fd arrays (count=0) return EINVAL.
 */
static int
test_empty_arrays(void)
{
	int cacl_fd;
	struct cacl_fds cf;
	struct cacl_members cm;
	int ret;
	int dummy_fd = 0;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* ADD_SELF with zero count. */
	cf.cf_cap_fds = &dummy_fd;
	cf.cf_cap_count = 0;
	ret = ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);
	ASSERT(ret != 0, "ADD_SELF with count=0 should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	/* CLEAR with zero count. */
	ret = ioctl(cacl_fd, CACL_IOC_CLEAR, &cf);
	ASSERT(ret != 0, "CLEAR with count=0 should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	/* ADD with zero cap count. */
	cm.cm_cap_fds = &dummy_fd;
	cm.cm_cap_count = 0;
	cm.cm_proc_fds = &dummy_fd;
	cm.cm_proc_count = 1;
	ret = ioctl(cacl_fd, CACL_IOC_ADD, &cm);
	ASSERT(ret != 0, "ADD with cap_count=0 should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	/* ADD with zero proc count. */
	cm.cm_cap_count = 1;
	cm.cm_proc_count = 0;
	ret = ioctl(cacl_fd, CACL_IOC_ADD, &cm);
	ASSERT(ret != 0, "ADD with proc_count=0 should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	close(cacl_fd);
	PASS();
}

/*
 * Test: Excessive count values return EINVAL.
 */
static int
test_excessive_count(void)
{
	int cacl_fd, pipe_r, pipe_w;
	struct cacl_fds cf;
	struct cacl_members cm;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* ADD_SELF with excessive count. */
	cf.cf_cap_fds = &pipe_w;
	cf.cf_cap_count = 10000;	/* > CACL_MAX_FDS (1024) */
	ret = ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);
	ASSERT(ret != 0, "ADD_SELF with excessive count should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	/* ADD with excessive cap count. */
	cm.cm_cap_fds = &pipe_w;
	cm.cm_cap_count = 2000;
	cm.cm_proc_fds = &pipe_r;
	cm.cm_proc_count = 1;
	ret = ioctl(cacl_fd, CACL_IOC_ADD, &cm);
	ASSERT(ret != 0, "ADD with excessive cap_count should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	/* ADD with excessive proc count. */
	cm.cm_cap_count = 1;
	cm.cm_proc_count = 2000;
	ret = ioctl(cacl_fd, CACL_IOC_ADD, &cm);
	ASSERT(ret != 0, "ADD with excessive proc_count should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Invalid fd in array returns error.
 */
static int
test_invalid_fd_in_array(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int fds[3];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Array with invalid fd in middle. */
	fds[0] = pipe_w;
	fds[1] = 9999;		/* Invalid fd. */
	fds[2] = pipe_r;

	ret = cacl_add_self(cacl_fd, fds, 3);
	ASSERT(ret != 0, "add_self with invalid fd should fail");
	ASSERT_EQ(errno, EBADF, "expected EBADF");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Multiple valid fds in single call.
 */
static int
test_multiple_fds(void)
{
	int cacl_fd;
	int pipes[3][2];
	int cap_fds[3];
	int ret;
	int i;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create 3 pipes. */
	for (i = 0; i < 3; i++) {
		ret = create_pipe(&pipes[i][0], &pipes[i][1]);
		ASSERT(ret == 0, "create_pipe failed");
		cap_fds[i] = pipes[i][1];
	}

	/* Add self to all 3 in single call. */
	ret = cacl_add_self(cacl_fd, cap_fds, 3);
	ASSERT_EQ(ret, 0, "add_self to multiple fds failed");

	/* Verify we can write to all 3. */
	for (i = 0; i < 3; i++) {
		ret = write(pipes[i][1], "x", 1);
		ASSERT_EQ(ret, 1, "write to pipe failed");
	}

	/* Clear all 3 in single call. */
	ret = cacl_clear(cacl_fd, cap_fds, 3);
	ASSERT_EQ(ret, 0, "clear multiple fds failed");

	for (i = 0; i < 3; i++) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	close(cacl_fd);
	PASS();
}

/*
 * Test: Mixed fd types in single call.
 */
static int
test_mixed_fd_types(void)
{
	int cacl_fd;
	int pipe_r, pipe_w;
	int sock_fd;
	int fds[2];
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(sock_fd >= 0, "socket failed");

	/* Mix pipe and socket in single call. */
	fds[0] = pipe_w;
	fds[1] = sock_fd;

	ret = cacl_add_self(cacl_fd, fds, 2);
	ASSERT_EQ(ret, 0, "add_self to mixed types failed");

	/* Clear both. */
	ret = cacl_clear(cacl_fd, fds, 2);
	ASSERT_EQ(ret, 0, "clear mixed types failed");

	close(pipe_r);
	close(pipe_w);
	close(sock_fd);
	close(cacl_fd);
	PASS();
}

/*
 * Test: Ioctl on closed cacl fd fails.
 */
static int
test_closed_cacl_fd(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Close the cacl fd. */
	close(cacl_fd);

	/* Try to use it - should fail. */
	ret = cacl_add_self(cacl_fd, &pipe_w, 1);
	ASSERT(ret != 0, "ioctl on closed fd should fail");
	ASSERT_EQ(errno, EBADF, "expected EBADF");

	close(pipe_r);
	close(pipe_w);
	PASS();
}

/*
 * Test: Operations on unsupported fd type.
 */
static int
test_unsupported_fd_type(void)
{
	int cacl_fd, kq_fd;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* kqueue is not supported. */
	kq_fd = kqueue();
	ASSERT(kq_fd >= 0, "kqueue failed");

	ret = cacl_add_self(cacl_fd, &kq_fd, 1);
	ASSERT(ret != 0, "add_self on kqueue should fail");
	ASSERT_EQ(errno, EOPNOTSUPP, "expected EOPNOTSUPP");

	ret = cacl_clear(cacl_fd, &kq_fd, 1);
	ASSERT(ret != 0, "clear on kqueue should fail");
	ASSERT_EQ(errno, EOPNOTSUPP, "expected EOPNOTSUPP");

	close(kq_fd);
	close(cacl_fd);
	PASS();
}

/*
 * Test: ADD with non-procdesc fd fails.
 */
static int
test_add_non_procdesc(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Try to add using pipe as process descriptor. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &pipe_r, 1);
	ASSERT(ret != 0, "add with non-procdesc should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_ioctl ===\n");

	ret = test_invalid_command();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_empty_arrays();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_excessive_count();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_invalid_fd_in_array();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_multiple_fds();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_mixed_fd_types();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_closed_cacl_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_unsupported_fd_type();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_add_non_procdesc();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
