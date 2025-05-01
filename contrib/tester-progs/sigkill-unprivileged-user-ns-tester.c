// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/capability.h>

#define pu64(ptr) ((__u64)((uintptr_t)(ptr)))

#ifndef __NR_clone3
#define __NR_clone3 -1
struct clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
};
#endif

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

static pid_t sys_clone3(struct clone_args *args)
{
	return syscall(__NR_clone3, args, sizeof(struct clone_args));
}

static int wait_for_pid(pid_t pid, int expected_sig)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		printf("Wait() for pid=%d failed\n", pid);
		return -1;
	}

	if (ret != pid)
		goto again;

	if (expected_sig) {
		if (WIFSIGNALED(status)) {
			int sig = WTERMSIG(status);
			if (sig == expected_sig) {
				printf("Wait() for pid=%d  child got signal %d. All good.\n", pid, sig);
				return 0;
			}

			printf("Wait() for pid=%d  child got signal %d, but expecting %d\n", pid, sig, expected_sig);
			return -1;
		} else  {
			printf("Wait() for pid=%d  child exited with %d, but expecting signal %d\n", pid, WEXITSTATUS(status), expected_sig);
			return -1;
		}
	} if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("Wait() for pid=%d  child exited with %d, but expecting success exit\n", pid, WEXITSTATUS(status));
		return -1;
	}

	printf("Wait() for pid=%d  child exited with success. All good.\n", pid);
	return 0;
}

static int check_cap(cap_value_t cap)
{
	int ret;
	cap_t caps;
	cap_flag_value_t value = 0;

	caps = cap_get_proc();
	if (caps == NULL)
		errExit("cap_get_proc");

	ret = cap_get_flag(caps, cap, CAP_EFFECTIVE, &value);
	if (ret)
		errExit("cap_get_flag");

	cap_free(caps);

	return value;
}

static void clear_cap(cap_value_t c)
{
	cap_t cap;
	cap_value_t cap_list[CAP_LAST_CAP+1];

	cap = cap_get_proc();
	if (cap == NULL)
		errExit("cap_get_proc");

	cap_list[0] = c;
	if (cap_set_flag(cap, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR) == -1)
		errExit("cap_set_flag");

	if (cap_set_proc(cap) == -1)
		errExit("cap_set_proc");

	cap_free(cap);
}

static void set_cap(cap_value_t c)
{
	cap_t cap;
	cap_value_t cap_list[CAP_LAST_CAP+1];

	cap = cap_get_proc();
	if (cap == NULL)
		errExit("cap_get_proc");

	cap_list[0] = c;
	if (cap_set_flag(cap, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1)
		errExit("cap_set_flag");

	if (cap_set_proc(cap) == -1)
		errExit("cap_set_proc");

	cap_free(cap);
}

static int unshare_pidns()
{
	return unshare(CLONE_NEWPID);
}

static int return_to_root_pidns(int fd)
{
	if (fd < 0)
		return fd;

	if (setns(fd, 0) == -1)
		return -1;

	close(fd);

	return 0;
}

static int get_my_pidns_fd()
{
	int fd = -1;

	fd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		errExit("open() /proc/self/ns/pid");

	return fd;
}

static int child_clone(int pipe[][2]) {
	int ret;
	pid_t parent_tid = -1, pid = -1, ppid = getpid();
	struct clone_args args = {
		/* CLONE_PARENT_SETTID */
		.parent_tid = pu64(&parent_tid),
		.flags = CLONE_NEWUSER | CLONE_PARENT_SETTID,
		.exit_signal = SIGCHLD,
	};

	// close pipe fds that we do not need.
	ret = close(pipe[0][1]);
	if (ret == -1)
		errExit("Child1: close() failed");

	ret = close(pipe[1][0]);
	if (ret == -1)
		errExit("Child1: close() failed");

	// redirect both stdout and stderr to the pipe that is read by
	// the parent.
	ret = dup2(pipe[1][1], STDOUT_FILENO);
	if (ret == -1)
		errExit("Child1: dup2() failed");

	ret = dup2(pipe[1][1], STDERR_FILENO);
	if (ret == -1)
		errExit("Child1: dup2() failed");

	// wait for a character from parent
	char c;
	ret = read(pipe[0][0], &c, 1);
	if (ret == 1)
		close(pipe[0][0]);
	else
		errExit("Child1: read() from parent failed");

	pid = sys_clone3(&args);
	if (pid < 0)
		errExit("Child1: clone() failed");

	if (pid == 0) {
		printf("Child2: (pid:%d) clone() succeeded\n", getpid());
		return 0;
	}

	printf("Child1: (pid:%d) clone() child2 (pid:%d)\n", ppid, *(pid_t *)args.parent_tid);

	if (wait_for_pid(pid, 0)) {
		printf("Child1: (pid:%d) failed to wait for child2 (pid:%d)\n", ppid, pid);
		exit(EXIT_FAILURE);
	}

	if (pid != parent_tid) {
		printf("Child1: (pid:%d) clone() failed pid mismatch on child2: %d != %d", ppid, pid, parent_tid);
		exit(EXIT_FAILURE);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int pipe[2][2];
	char buff[1024];
	int expected_sig = 9;
	pid_t pid, ppid = getpid();
	int err, cap, restore = 0, fd = -1;

	// pipe[0]: parent writes to child
	// pipe[1]: child writes to parent
	if (pipe2(pipe[0], O_DIRECT) == -1)
		errExit("pipe2");
	if (pipe2(pipe[1], O_DIRECT) == -1)
		errExit("pipe2");

	printf("%d\n", ppid);
	cap = check_cap(CAP_SYS_ADMIN);
	if (cap) {
		restore = cap;
		printf("Parent: (pid:%d) checking capability CAP_SYS_ADMIN: is set\n", ppid);
		/* Run from pid namespace */
		if (argc > 1) {
			fd = get_my_pidns_fd();
			printf("Parent: (pid:%d) unsharing pid namespace\n", ppid);
			if (unshare_pidns() < 0)
				errExit("Parent: failed to unshare pid namespace");
		}
		printf("Parent: (pid:%d) clearing capability CAP_SYS_ADMIN\n", ppid);
		clear_cap(CAP_SYS_ADMIN);
		cap = check_cap(CAP_SYS_ADMIN);
	}

	if (cap) {
		errExit("Parent: failed to clear CAP_SYS_ADMIN capability");
	} else {
		printf("Parent: (pid:%d) checking capability CAP_SYS_ADMIN: not set\n", ppid);
		if (!restore && argc > 1) {
			printf("Parent: (pid:%d) capability CAP_SYS_ADMIN is not set, can not unshare pid namespace\n", ppid);
			printf("Parent: (pid:%d) clone(CLONE_NEWUSER) TEST SKIPPED\n", ppid);
			return 0;
		}
	}

	pid = fork();
	if (pid < 0) {
		perror("Parent: fork()");
		goto out;
	}

	if (pid == 0) {
		child_clone(pipe);
		return 0;
	}

	fflush(stdout);

	// close pipe fds that we do not need.
	err = close(pipe[0][0]);
	if (err == -1) {
		perror("Parent: close()");
		goto out;
	}
	err = close(pipe[1][1]);
	if (err == -1) {
		perror("Parent: close()");
		goto out;
	}

	printf("Parent: (pid:%d) waiting for input in stdin\n", ppid);
	fflush(stdout);

	int rd = read(0, buff, sizeof(buff));
	if (rd <= 0) {
		perror("Parent: read() failed");
		goto out;
	}

	// write a single character to child
	printf("Parent: (pid:%d) waking up child1 (pid:%d)\n", ppid, pid);
	write(pipe[0][1], buff, 1);
	close(pipe[0][1]);

	// read messages from child, and print them to stdout.
	printf("Parent: (pid:%d) reading messages from child1 (pid:%d)\n", ppid, pid);
	for (;;) {
		int rd = read(pipe[1][0], buff, sizeof(buff));
		if (rd == 0) {
			break;
		} else if (rd < 0){
			perror("Parent: read()");
			goto out;
		}

		write(1, buff, rd);
	}

	printf("Parent: (pid:%d) waiting for child1 (pid:%d)\n", ppid, pid);
	err = wait_for_pid(pid, expected_sig);

out:
	if (restore) {
		printf("Parent: (pid:%d) restoring capability CAP_SYS_ADMIN\n", ppid);
		set_cap(CAP_SYS_ADMIN);
	}

	return_to_root_pidns(fd);

	printf("Parent: (pid:%d) clone(CLONE_NEWUSER) TEST %s\n", ppid, (err < 0) ? "FAILED" : "SUCCEEDED");

	fflush(stdout);
	return err;
}
