/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test error handling.
 *
 * Verifies:
 * 1. Invalid fd returns appropriate error
 * 2. Unsupported fd types (kqueue) return EOPNOTSUPP
 * 3. Invalid process descriptor returns error
 * 4. Bounds checking on ioctl parameters
 */

#include "test_common.h"
#include <fcntl.h>
#include <sys/event.h>

static int
test_invalid_fd(void)
{
	int cacl_fd;
	int bad_fd = 999;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Try to add self to invalid fd. */
	ret = cacl_add_self(cacl_fd, &bad_fd, 1);
	ASSERT(ret != 0, "add_self with invalid fd should fail");
	ASSERT_EQ(errno, EBADF, "expected EBADF for invalid fd");

	close(cacl_fd);
	PASS();
}

static int
test_unsupported_type(void)
{
	int cacl_fd, kq_fd;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a kqueue - this type is not supported. */
	kq_fd = kqueue();
	ASSERT(kq_fd >= 0, "kqueue failed");

	/* Try to add self to kqueue - should fail with EOPNOTSUPP. */
	ret = cacl_add_self(cacl_fd, &kq_fd, 1);
	ASSERT(ret != 0, "add_self on kqueue should fail");
	ASSERT_EQ(errno, EOPNOTSUPP, "expected EOPNOTSUPP for kqueue");

	close(kq_fd);
	close(cacl_fd);
	PASS();
}

static int
test_invalid_proc_fd(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int bad_proc_fd = 998;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Try to add with invalid process descriptor. */
	ret = cacl_add(cacl_fd, &pipe_w, 1, &bad_proc_fd, 1);
	ASSERT(ret != 0, "add with invalid proc_fd should fail");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

static int
test_not_proc_fd(void)
{
	int cacl_fd, pipe_r, pipe_w;
	int not_proc_fd;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Use pipe as "process descriptor" - should fail. */
	not_proc_fd = pipe_r;
	ret = cacl_add(cacl_fd, &pipe_w, 1, &not_proc_fd, 1);
	ASSERT(ret != 0, "add with non-proc fd should fail");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

static int
test_bounds_checking(void)
{
	int cacl_fd, pipe_r, pipe_w;
	struct cacl_fds cf;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&pipe_r, &pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Try to pass more than CACL_MAX_FDS (1024) fds. */
	cf.cf_cap_fds = &pipe_w;
	cf.cf_cap_count = 2000;  /* Exceeds CACL_MAX_FDS */
	ret = ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);
	ASSERT(ret != 0, "add_self with excessive count should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL for excessive count");

	close(pipe_r);
	close(pipe_w);
	close(cacl_fd);
	PASS();
}

static int
test_zero_count(void)
{
	int cacl_fd;
	struct cacl_fds cf;
	int ret;

	cacl_fd = cacl_open();
	if (cacl_fd < 0)
		return (TEST_SKIP);

	/* Try to pass zero fds. */
	cf.cf_cap_fds = NULL;
	cf.cf_cap_count = 0;
	ret = ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);
	ASSERT(ret != 0, "add_self with zero count should fail");
	ASSERT_EQ(errno, EINVAL, "expected EINVAL for zero count");

	close(cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_errors ===\n");

	ret = test_invalid_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_unsupported_type();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_invalid_proc_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_not_proc_fd();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_bounds_checking();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_zero_count();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
