/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Multithreading tests for CACL.
 *
 * Tests concurrent access patterns:
 * - Concurrent adds to same ACL
 * - Concurrent add/remove operations
 * - Concurrent read access while modifying
 * - Stress test with many threads
 */

#include "test_common.h"
#include <pthread.h>
#include <sys/socket.h>

#define	NUM_THREADS	8
#define	NUM_ITERATIONS	100

/* Shared state for thread tests. */
static int g_cacl_fd;
static int g_pipe_r, g_pipe_w;
static int g_errors;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
record_error(void)
{
	pthread_mutex_lock(&g_mutex);
	g_errors++;
	pthread_mutex_unlock(&g_mutex);
}

/*
 * Thread function: repeatedly add self to ACL.
 */
static void *
thread_add_self(void *arg __unused)
{
	int i;

	for (i = 0; i < NUM_ITERATIONS; i++) {
		if (cacl_add_self(g_cacl_fd, &g_pipe_w, 1) != 0) {
			if (errno != ENOSPC)	/* ENOSPC is acceptable. */
				record_error();
		}
	}
	return (NULL);
}

/*
 * Test: Multiple threads adding self concurrently.
 */
static int
test_concurrent_add(void)
{
	pthread_t threads[NUM_THREADS];
	int ret;
	int i;

	g_cacl_fd = cacl_open();
	if (g_cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&g_pipe_r, &g_pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	g_errors = 0;

	/* Start threads. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = pthread_create(&threads[i], NULL, thread_add_self, NULL);
		ASSERT(ret == 0, "pthread_create failed");
	}

	/* Wait for threads. */
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	ASSERT_EQ(g_errors, 0, "errors during concurrent add");

	/* Verify ACL is valid - we should have access. */
	ret = write(g_pipe_w, "x", 1);
	ASSERT_EQ(ret, 1, "write after concurrent adds failed");

	close(g_pipe_r);
	close(g_pipe_w);
	close(g_cacl_fd);
	PASS();
}

/* Shared state for add/clear test. */
static volatile int g_stop;

/*
 * Thread function: repeatedly add self.
 */
static void *
thread_adder(void *arg __unused)
{
	while (!g_stop) {
		cacl_add_self(g_cacl_fd, &g_pipe_w, 1);
		usleep(100);
	}
	return (NULL);
}

/*
 * Thread function: repeatedly clear ACL.
 */
static void *
thread_clearer(void *arg __unused)
{
	while (!g_stop) {
		cacl_clear(g_cacl_fd, &g_pipe_w, 1);
		usleep(100);
	}
	return (NULL);
}

/*
 * Test: Concurrent add and clear operations.
 */
static int
test_concurrent_add_clear(void)
{
	pthread_t adders[4], clearers[2];
	int ret;
	int i;

	g_cacl_fd = cacl_open();
	if (g_cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&g_pipe_r, &g_pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	g_stop = 0;
	g_errors = 0;

	/* Start adder threads. */
	for (i = 0; i < 4; i++) {
		ret = pthread_create(&adders[i], NULL, thread_adder, NULL);
		ASSERT(ret == 0, "pthread_create failed");
	}

	/* Start clearer threads. */
	for (i = 0; i < 2; i++) {
		ret = pthread_create(&clearers[i], NULL, thread_clearer, NULL);
		ASSERT(ret == 0, "pthread_create failed");
	}

	/* Let them run for a bit. */
	usleep(100000);	/* 100ms */

	g_stop = 1;

	/* Wait for threads. */
	for (i = 0; i < 4; i++)
		pthread_join(adders[i], NULL);
	for (i = 0; i < 2; i++)
		pthread_join(clearers[i], NULL);

	/* No crashes = success. */
	close(g_pipe_r);
	close(g_pipe_w);
	close(g_cacl_fd);
	PASS();
}

/*
 * Thread function: try to write to pipe.
 */
static void *
thread_writer(void *arg __unused)
{
	int i;
	char buf[1] = {'x'};

	for (i = 0; i < NUM_ITERATIONS; i++) {
		/* May succeed or fail depending on ACL state. */
		(void)write(g_pipe_w, buf, 1);
		usleep(10);
	}
	return (NULL);
}

/*
 * Test: Concurrent writes while ACL is being modified.
 */
static int
test_concurrent_write(void)
{
	pthread_t writers[4], modifiers[2];
	int ret;
	int i;

	g_cacl_fd = cacl_open();
	if (g_cacl_fd < 0)
		return (TEST_SKIP);

	ret = create_pipe(&g_pipe_r, &g_pipe_w);
	ASSERT(ret == 0, "create_pipe failed");

	/* Add self initially. */
	ret = cacl_add_self(g_cacl_fd, &g_pipe_w, 1);
	ASSERT_EQ(ret, 0, "initial add_self failed");

	g_stop = 0;

	/* Start writer threads. */
	for (i = 0; i < 4; i++) {
		ret = pthread_create(&writers[i], NULL, thread_writer, NULL);
		ASSERT(ret == 0, "pthread_create failed");
	}

	/* Start modifier threads (add/clear). */
	ret = pthread_create(&modifiers[0], NULL, thread_adder, NULL);
	ASSERT(ret == 0, "pthread_create failed");
	ret = pthread_create(&modifiers[1], NULL, thread_clearer, NULL);
	ASSERT(ret == 0, "pthread_create failed");

	/* Let them run. */
	usleep(100000);

	g_stop = 1;

	/* Wait for threads. */
	for (i = 0; i < 4; i++)
		pthread_join(writers[i], NULL);
	pthread_join(modifiers[0], NULL);
	pthread_join(modifiers[1], NULL);

	/* Drain the pipe. */
	{
		char buf[1024];
		int flags = fcntl(g_pipe_r, F_GETFL);
		fcntl(g_pipe_r, F_SETFL, flags | O_NONBLOCK);
		while (read(g_pipe_r, buf, sizeof(buf)) > 0)
			;
	}

	close(g_pipe_r);
	close(g_pipe_w);
	close(g_cacl_fd);
	PASS();
}

/*
 * Per-thread state for stress test.
 */
struct stress_args {
	int thread_id;
	int pipe_w;
	int iterations;
	int errors;
};

static void *
thread_stress(void *arg)
{
	struct stress_args *sa = arg;
	int i;

	for (i = 0; i < sa->iterations; i++) {
		int r = random() % 4;

		switch (r) {
		case 0:
			cacl_add_self(g_cacl_fd, &sa->pipe_w, 1);
			break;
		case 1:
			cacl_clear(g_cacl_fd, &sa->pipe_w, 1);
			break;
		case 2:
			write(sa->pipe_w, "x", 1);
			break;
		case 3:
			usleep(1);
			break;
		}
	}
	return (NULL);
}

/*
 * Test: Stress test with many threads doing random operations.
 */
static int
test_stress(void)
{
	pthread_t threads[NUM_THREADS];
	struct stress_args args[NUM_THREADS];
	int pipes[NUM_THREADS][2];
	int ret;
	int i;

	g_cacl_fd = cacl_open();
	if (g_cacl_fd < 0)
		return (TEST_SKIP);

	/* Create a pipe per thread. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = create_pipe(&pipes[i][0], &pipes[i][1]);
		ASSERT(ret == 0, "create_pipe failed");
		args[i].thread_id = i;
		args[i].pipe_w = pipes[i][1];
		args[i].iterations = 500;
		args[i].errors = 0;
	}

	/* Start threads. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = pthread_create(&threads[i], NULL, thread_stress, &args[i]);
		ASSERT(ret == 0, "pthread_create failed");
	}

	/* Wait for threads. */
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	/* Clean up. */
	for (i = 0; i < NUM_THREADS; i++) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	close(g_cacl_fd);

	/* No crashes = success. */
	PASS();
}

/*
 * Test: Multiple pipes with sequential operations (baseline).
 */
static int
test_parallel_pipes(void)
{
	int pipes[NUM_THREADS][2];
	int ret;
	int i;

	g_cacl_fd = cacl_open();
	if (g_cacl_fd < 0)
		return (TEST_SKIP);

	/* Create multiple pipes. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = create_pipe(&pipes[i][0], &pipes[i][1]);
		ASSERT(ret == 0, "create_pipe failed");
	}

	/* Add self to all pipes. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = cacl_add_self(g_cacl_fd, &pipes[i][1], 1);
		ASSERT_EQ(ret, 0, "add_self failed");
	}

	/* All pipes should be writable. */
	for (i = 0; i < NUM_THREADS; i++) {
		ret = write(pipes[i][1], "x", 1);
		ASSERT_EQ(ret, 1, "write to parallel pipe failed");
	}

	/* Clean up. */
	for (i = 0; i < NUM_THREADS; i++) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	close(g_cacl_fd);
	PASS();
}

int
main(void)
{
	int ret;

	printf("=== test_threads ===\n");

	ret = test_concurrent_add();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_concurrent_add_clear();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_concurrent_write();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_stress();
	if (ret != TEST_PASS)
		return (ret);

	ret = test_parallel_pipes();
	if (ret != TEST_PASS)
		return (ret);

	return (TEST_PASS);
}
