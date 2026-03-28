TESTS=	test_add_self \
	test_add \
	test_remove \
	test_clear \
	test_exec \
	test_fork \
	test_socket \
	test_socket_ops \
	test_pipe_ops \
	test_shm \
	test_vnode \
	test_multi \
	test_errors \
	test_unit \
	test_ioctl \
	test_threads \
	test_edge \
	test_comprehensive

HELPERS= test_helper

CFLAGS=	-Wall -Wextra -Werror -g -O0
LDFLAGS=

.PHONY: all clean test

all: $(TESTS) $(HELPERS)

test_add_self: test_add_self.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_add_self.c $(LDFLAGS)

test_add: test_add.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_add.c $(LDFLAGS)

test_remove: test_remove.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_remove.c $(LDFLAGS)

test_clear: test_clear.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_clear.c $(LDFLAGS)

test_exec: test_exec.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_exec.c $(LDFLAGS)

test_fork: test_fork.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_fork.c $(LDFLAGS)

test_socket: test_socket.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_socket.c $(LDFLAGS)

test_socket_ops: test_socket_ops.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_socket_ops.c $(LDFLAGS)

test_pipe_ops: test_pipe_ops.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_pipe_ops.c $(LDFLAGS)

test_shm: test_shm.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_shm.c $(LDFLAGS)

test_vnode: test_vnode.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_vnode.c $(LDFLAGS)

test_multi: test_multi.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_multi.c $(LDFLAGS)

test_errors: test_errors.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_errors.c $(LDFLAGS)

test_unit: test_unit.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_unit.c $(LDFLAGS)

test_ioctl: test_ioctl.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_ioctl.c $(LDFLAGS)

test_threads: test_threads.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_threads.c $(LDFLAGS) -lpthread

test_edge: test_edge.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_edge.c $(LDFLAGS)

test_comprehensive: test_comprehensive.c test_common.h ../cacl.h
	$(CC) $(CFLAGS) -o $@ test_comprehensive.c $(LDFLAGS)

test_helper: test_helper.c
	$(CC) $(CFLAGS) -o $@ test_helper.c $(LDFLAGS)

test: all
	@./run_tests.sh

clean:
	rm -f $(TESTS) $(HELPERS)
