// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/io.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/capability.h>

#define IO_DELAY 0x80

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

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

int check_cap()
{
	int ret;
	cap_t caps;
	cap_flag_value_t value = 0;

	caps = cap_get_proc();
	if (caps == NULL)
		errExit("cap_get_proc");

	ret = cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &value);
	if (ret)
		errExit("cap_get_flag");

	cap_free(caps);

	return value;
}

void clear_cap(cap_value_t c)
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

void set_cap(cap_value_t c)
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

int unshare_pidns()
{
	return unshare(CLONE_NEWPID);
}

int return_to_root_pidns(int fd)
{
	if (fd < 0)
		return fd;

	if (setns(fd, 0) == -1)
		return -1;

	close(fd);

	return 0;
}

int get_my_pidns_fd()
{
	int fd = -1;

	fd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		errExit("open() /proc/self/ns/pid");

	return fd;
}

int child_ioperm(int pipe[][2]) {
	int ret;
	pid_t pid = getpid();

	// close pipe fds that we do not need.
	ret = close(pipe[0][1]);
	if (ret == -1)
		errExit("Child: close() failed");

	ret = close(pipe[1][0]);
	if (ret == -1)
		errExit("Child: close() failed");

	// redirect both stdout and stderr to the pipe that is read by
	// the parent.
	ret = dup2(pipe[1][1], STDOUT_FILENO);
	if (ret == -1)
		errExit("Child: dup2() failed");

	ret = dup2(pipe[1][1], STDERR_FILENO);
	if (ret == -1)
		errExit("Child: dup2() failed");

	// wait for a character from parent
	char c;
	ret = read(pipe[0][0], &c, 1);
	if (ret == 1)
		close(pipe[0][0]);
	else
		errExit("Child: read() from parent failed");

	/* probe the port */
	ret = ioperm(IO_DELAY, 1, 1);
	if (ret < 0)
		errExit("Child: ioperm() failed");

	printf("Child: (pid:%d) ioperm(0x%02x, 1, 1) enabled access with success\n", pid, IO_DELAY);

	/* Disable again */
	ret = ioperm(IO_DELAY, 1, 0);
	if (!ret)
		printf("Child: (pid:%d) ioperm(0x%02x, 1, 0) disabled access\n", pid, IO_DELAY);

	return 0;
}

int main(int argc, char *argv[])
{
	int pipe[2][2];
	char buff[1024];
	int expected_sig = 9;
	pid_t pid, ppid = getpid();
	int err, cap, fd = -1;

	// pipe[0]: parent writes to child
	// pipe[1]: child writes to parent
	if (pipe2(pipe[0], O_DIRECT) == -1)
		errExit("pipe2");
	if (pipe2(pipe[1], O_DIRECT) == -1)
		errExit("pipe2");

	printf("%d\n", ppid);
	cap = check_cap(CAP_SYS_ADMIN);
	if (cap) {
		printf("Parent: (pid:%d) checking capability CAP_SYS_ADMIN: is set\n", ppid);
		/* Run from pid namespace */
		fd = get_my_pidns_fd();
		printf("Parent: (pid:%d) unsharing pid namespace\n", ppid);
		if (unshare_pidns() < 0)
			errExit("Parent: failed to unshare pid namespace");
	} else {
		printf("Parent: (pid:%d) capability CAP_SYS_ADMIN is not set, can not unshare pid namespace\n", ppid);
		printf("Parent: (pid:%d) kill ioperm() syscall: TEST SKIPPED\n", ppid);
		return 0;
	}

	pid = fork();
	if (pid < 0) {
		perror("Parent: fork()");
		goto out;
	}

	if (pid == 0) {
		child_ioperm(pipe);
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
	return_to_root_pidns(fd);

	printf("Parent: (pid:%d) kill ioperm() syscall: TEST %s\n", ppid, (err < 0) ? "FAILED" : "SUCCEEDED");

	fflush(stdout);
	return err;
}