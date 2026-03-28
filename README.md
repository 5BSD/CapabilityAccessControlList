# CACL - Capability Access Control List

A FreeBSD kernel module that controls which processes can use specific file
descriptors. CACL extends the capability model by allowing fine-grained,
per-descriptor access control based on process identity.

## The Problem

In Unix, **possession of a file descriptor grants the ability to use it**.
This creates two problems:

### 1. Uncontrolled Propagation

Once you give a descriptor to another process, they can pass it to anyone:

```
You create a pipe, give it to Process A (trusted)
                │
                ▼
        Process A passes it to Process B via SCM_RIGHTS
                │
                ▼
        Process B passes it to Process C
                │
                ▼
        You have no way to prevent this
```

### 2. Exec Changes the Program, Not the Access

When a process exec's a new program, it keeps its file descriptors. A
descriptor you intended for one program is now available to a completely
different program:

```
You fork a child, give it an fd for communication
                │
                ▼
        Child exec's "trusted_helper" - works as intended
                │
                ▼
        But what if child exec's "malicious_program" instead?
                │
                ▼
        malicious_program has full access to your fd
```

### What About Capsicum?

Capsicum capabilities let you restrict *what operations* a descriptor allows
(read-only, no seek, etc.), but they don't control *who* can use it:

- A capability-restricted fd can still be passed to other processes
- A capability-restricted fd survives exec into a different program
- The recipient has whatever rights the capability allows

**Capsicum controls what you can do. CACL controls who can do it.**

## The Solution

CACL makes access depend on **process identity**, not just possession.
Each descriptor has an access control list. Only processes whose token is
in the ACL can use it.

**Two key behaviors:**

1. **Propagation is useless**: If Process A passes an fd to Process B,
   and B is not in the ACL, B gets EACCES on any operation.

2. **Exec invalidates access**: When a process calls exec(), it gets a new
   token. If the new token isn't in the ACL, the descriptor becomes unusable.

```
Descriptor with ACL: [token_A, token_B]

Process A (token_A) ──► Can use it ✓
        │
        │ passes fd to Process C
        ▼
Process C (token_C) ──► EACCES ✗ (not in ACL)

Process B (token_B) ──► Can use it ✓
        │
        │ calls exec("new_program")
        ▼
Process B (token_X) ──► EACCES ✗ (new token after exec)
```

**The descriptor is bound to specific process images, not just possession.**

## Quick Start

### Building

```sh
make              # Build cacl.ko
cd tests && make  # Build tests
```

### Loading

```sh
kldload ./cacl.ko
ls -la /dev/cacl  # Should exist with mode 0666
```

### Basic Usage

```c
#include <sys/ioctl.h>
#include "cacl.h"

int main() {
    int cacl_fd, pipefd[2];

    /* Open control device */
    cacl_fd = open("/dev/cacl", O_RDWR);

    /* Create a pipe */
    pipe(pipefd);

    /* Add ourselves to the pipe's access list */
    struct cacl_fds cf = {
        .cf_cap_fds = &pipefd[1],
        .cf_cap_count = 1
    };
    ioctl(cacl_fd, CACL_IOC_ADD_SELF, &cf);

    /* Now only we can write to pipefd[1] */
    /* Any exec'd child will be denied */

    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c",
              "echo test >&3", NULL);  /* Will fail with EACCES */
    }

    close(cacl_fd);
    return 0;
}
```

## Use Cases

### 1. Preventing Unauthorized FD Passing

You give a socket to a worker, but don't want the worker to share it:

```c
int sv[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

/* Only allow yourself and the worker */
cacl_add_self(cacl_fd, &sv[0], 1);
cacl_add(cacl_fd, &sv[0], 1, &worker_proc_fd, 1);

/* Send sv[0] to worker via SCM_RIGHTS - worker can use it */

/* If worker sends sv[0] to another process... */
/* ...that process gets EACCES when trying to use it */
```

### 2. Protecting IPC Channels After Exec

Prevent exec'd helper programs from accessing parent's communication channels:

```c
int sv[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

/* Protect before exec */
cacl_add_self(cacl_fd, &sv[0], 1);

pid_t pid = fork();
if (pid == 0) {
    /* Child inherits sv[0] but after exec... */
    execl("./untrusted_helper", "helper", NULL);
    /* ...helper cannot read/write sv[0] */
}

/* Parent communicates with child via sv[1] */
/* Child's stdin/stdout, but not sv[0] */
```

### 3. Controlled Delegation with Process Descriptors

Grant specific child processes access using pdfork():

```c
int pipe_w;  /* Write end of pipe */
int proc_fd;

/* Fork child with process descriptor */
pid_t pid = pdfork(&proc_fd, 0);
if (pid == 0) {
    /* Child waits for work */
    child_main();
}

/* Parent decides child should have pipe access */
struct cacl_members cm = {
    .cm_cap_fds = &pipe_w,
    .cm_cap_count = 1,
    .cm_proc_fds = &proc_fd,
    .cm_proc_count = 1
};
ioctl(cacl_fd, CACL_IOC_ADD, &cm);

/* Child can now write to pipe */
/* Other processes still denied */
```

### 4. Revoking Access

Remove access when no longer needed:

```c
/* Add child to ACL */
cacl_add(cacl_fd, &pipe_w, 1, &proc_fd, 1);

/* ... child does work ... */

/* Revoke access */
cacl_remove(cacl_fd, &pipe_w, 1, &proc_fd, 1);

/* Child's next write() returns EACCES */
```

### 5. Batch Operations

Add multiple processes to multiple descriptors in one call:

```c
int cap_fds[3] = { pipe1_w, pipe2_w, socket_fd };
int proc_fds[2] = { worker1_pd, worker2_pd };

struct cacl_members cm = {
    .cm_cap_fds = cap_fds,
    .cm_cap_count = 3,
    .cm_proc_fds = proc_fds,
    .cm_proc_count = 2
};

/* All 2 workers get access to all 3 descriptors */
ioctl(cacl_fd, CACL_IOC_ADD, &cm);
```

## API Reference

### Device

Open `/dev/cacl` for ioctl operations:
```c
int cacl_fd = open("/dev/cacl", O_RDWR);
```

### Ioctl Commands

| Command | Description | Argument |
|---------|-------------|----------|
| `CACL_IOC_ADD_SELF` | Add calling process to ACLs | `struct cacl_fds` |
| `CACL_IOC_ADD` | Add processes (by procdesc) to ACLs | `struct cacl_members` |
| `CACL_IOC_REMOVE` | Remove processes from ACLs | `struct cacl_members` |
| `CACL_IOC_CLEAR` | Clear ACLs (return to default-allow) | `struct cacl_fds` |

### Structures

```c
struct cacl_fds {
    int      *cf_cap_fds;    /* Array of descriptor fds */
    uint16_t  cf_cap_count;  /* Number of descriptors */
};

struct cacl_members {
    int      *cm_cap_fds;    /* Array of descriptor fds */
    uint16_t  cm_cap_count;  /* Number of descriptors */
    int      *cm_proc_fds;   /* Array of process descriptor fds */
    uint16_t  cm_proc_count; /* Number of processes */
};
```

### Error Codes

| Error | Meaning |
|-------|---------|
| `EBADF` | Invalid file descriptor in array |
| `EINVAL` | Invalid count (0 or > 1024), or proc_fd is not a process descriptor |
| `EOPNOTSUPP` | Descriptor type not supported (kqueue, procdesc, etc.) |
| `ENOSPC` | ACL has reached maximum size (65536 tokens) |
| `ENOTTY` | Invalid ioctl command |

## How It Works

### Tokens

Each process has a unique 64-bit random token assigned at exec time:
- Forked children **inherit** their parent's token
- After exec(), the process gets a **new token**
- Pre-module processes have token 0 (always allowed)

### Access Control

When a process tries to use a protected descriptor:

1. If ACL is **empty**: ALLOW (default-allow policy)
2. If process token is **in ACL**: ALLOW
3. Otherwise: DENY with EACCES

### Supported Descriptor Types

| Type | Created By | Supported |
|------|------------|-----------|
| Pipes | `pipe()`, `pipe2()` | Yes |
| Sockets | `socket()`, `socketpair()` | Yes |
| POSIX SHM | `shm_open()` | Yes |
| Files/FIFOs | `open()` | Yes |
| kqueue | `kqueue()` | No |
| Process descriptors | `pdfork()` | No |
| Semaphores | `sem_open()` | No |
| Message queues | `mq_open()` | No |

### Operations Blocked

| Descriptor | Blocked Operations |
|------------|-------------------|
| Pipe | read, write, fstat, ioctl |
| Socket | send, recv, bind, connect, listen, accept, fstat |
| POSIX SHM | mmap, read, write, fstat, ftruncate |
| Vnode (file) | read, write, fstat, mmap |

## Limitations

### Not Blocked: poll()/select()

Unauthorized processes can still poll descriptors to detect readability/
writability, even though they cannot perform the actual I/O.

```c
/* This succeeds even if process not in ACL */
struct pollfd pfd = { .fd = protected_fd, .events = POLLIN };
poll(&pfd, 1, 0);  /* Returns, but read() would fail */
```

### Not Blocked: open() by Path

CACL protects the *descriptor*, not the underlying file. If an unauthorized
process knows the file path, it can open() a new descriptor:

```c
/* Process not in ACL for fd 5 */
write(5, "x", 1);  /* EACCES - blocked */

/* But if they know the path... */
int new_fd = open("/path/to/same/file", O_WRONLY);
write(new_fd, "x", 1);  /* Succeeds - new fd has no ACL */
```

**Mitigation**: Use CACL primarily for anonymous descriptors (pipes,
socketpairs, anonymous shm) where there's no path to open.

### Fork Inherits Token

Forked children share their parent's token until they exec:

```c
cacl_add_self(cacl_fd, &pipe_w, 1);

pid_t pid = fork();
if (pid == 0) {
    /* Child has same token as parent */
    write(pipe_w, "x", 1);  /* Succeeds! */

    execl("./helper", "helper", NULL);
    /* After exec, child has new token */
    write(pipe_w, "x", 1);  /* EACCES */
}
```

This is by design: fork() creates a copy of the process.

### Not a Sandbox

CACL is not a replacement for Capsicum or jail(). It controls descriptor
access, not system capabilities. A process denied access to one descriptor
can still:
- Open new files
- Create new sockets
- Fork and exec
- Make any other system call

## DTrace Probes

Monitor CACL activity:

```sh
# Watch access denials
dtrace -n 'cacl::deny { printf("%s pid=%d op=%s", execname, pid, arg0); }'

# Watch token changes (exec)
dtrace -n 'cacl::token-change { printf("%s pid=%d token=%x", execname, pid, arg0); }'

# Watch ACL modifications
dtrace -n 'cacl::acl-modify { printf("%s pid=%d op=%s", execname, pid, arg0); }'
```

## Sysctl

Enable verbose logging of access denials:

```sh
sysctl security.cacl_verbose=1
# Now denials are logged to kernel message buffer
dmesg | grep cacl
```

## Testing

```sh
cd tests
./run_tests.sh

# Or run individual tests
./test_exec
./test_socket
./test_comprehensive
```

## Unloading

```sh
kldunload cacl
```

## License

BSD-2-Clause
