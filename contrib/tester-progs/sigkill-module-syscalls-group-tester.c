// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/capability.h>

#define MODULE "kernel_module_hello.ko"
#define DELETE_MODULE "kernel_module_hello"

#define finit_module(fd, param_values, flags) syscall(__NR_finit_module, fd, param_values, flags)
#define delete_module(name, flags) syscall(__NR_delete_module, name, flags)

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

int load_module(int pipe[][2], const char *dir, const char *kmod) {
	int ret, fd;
	struct stat st;
	char buf[1024];
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

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%s/%s.ko", dir, kmod);
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		errExit("Child: open() kernel module failed");

	ret = fstat(fd, &st);
	if (ret < 0)
		errExit("Child: fstat() kernel module failed");

	ret = finit_module(fd, "", 0);
	if (ret == -EEXIST) {
		delete_module(kmod, 0);
		ret = finit_module(fd, "", 0);
	}
	if (ret < 0)
		errExit("Child: finit_module() kernel module failed");

	printf("Child: (pid:%d) finit_module() succeeded\n", pid);

	close(fd);
	return 0;
}

int main(int argc, char *argv[])
{
	int pipe[2][2];
	char buff[1024];
	int expected_sig = 9;
	pid_t pid, ppid = getpid();
	int err, cap, fd = -1;

	if (argc < 3)
		errExit("passed arguments error");

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
		printf("Parent: (pid:%d) kill finit_module() syscall: TEST SKIPPED\n", ppid);
		return 0;
	}

	pid = fork();
	if (pid < 0) {
		perror("Parent: fork()");
		goto out;
	}

	if (pid == 0) {
		load_module(pipe, argv[1], argv[2]);
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
	delete_module(argv[2], 0);
	return_to_root_pidns(fd);

	printf("Parent: (pid:%d) kill finit_module() syscall: TEST %s\n", ppid, (err < 0) ? "FAILED" : "SUCCEEDED");

	fflush(stdout);
	return err;
}