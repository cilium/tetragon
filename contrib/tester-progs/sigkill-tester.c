// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>


/**
 * sigkill-tester: tester for Tetragon's sigkill action
 *
 * This program will fork() a new process, and it will create two pipes so that
 * it can talk to the child and the child can talk to it. The process will print
 * the child PID, and then wait for a single character in its stdin. Once it
 * receives the character, it will wake up the child which will do an exec and
 * execute the child() function. Child will do a bogus lseek (one that we can
 * use as a trigger for the kill action in the tetragon kprobe spec), and then wait
 * until it gets killed.
 *
 * If the child is kild with a 9 signal (SIGKILL), process returns 0. Otherwise
 * it returns 1.
 *
 * TODO:
 *  - add a switch to specify what signal to expect (once we support signals
 *  other than SIGKILL in tetragon).
 *
 * FAQ:
 *  - Why did you write this in C?
 *    We want to execute this from the observer test. Obviously, we cannot kill
 *    the observer as part of the test. Go does not have fork(), so we need to
 *    exec something. But we also need to coordinate the process that will be
 *    killed with the observer, and this program was the easiest solution I
 *    could think of.
 */

int child()
{
	const int t = 1;
	sleep(t);
	printf("child will now do lseek\n");
	fflush(stdout);
	lseek(-1, 0, 5555 /* magic value */);
	printf("lseek done, going back to sleep\n");
	fflush(stdout);
	for (int i = 0; ; i++) {
		printf("[i=%d] child will sleep for %d sec(s)\n", i, t);
		fflush(stdout);
		sleep(t);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int pipe[2][2];
	int expected_sig = 9; // NB: tetragon only supports sigkill for now

	// this is what will the child will exec.
	if (!strcmp(argv[0], "child")) {
		return child();
	}

	// pipe[0]: parent writes to child
	// pipe[1]: child writes to parent
	if (pipe2(pipe[0], O_DIRECT) == -1) {
		perror("pipe2");
		exit(1);
	}
	if (pipe2(pipe[1], O_DIRECT) == -1) {
		perror("pipe2");
		exit(1);
	}


	if  ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		char *newargv[] = {"child", NULL};
		char *newenviron[] = { NULL };
		int ret;

		// close pipe fds that we do not need.
		ret = close(pipe[0][1]);
		if (ret == -1) {
			perror("close");
			exit(1);
		}

		ret = close(pipe[1][0]);
		if (ret == -1) {
			perror("close");
			exit(1);
		}

		// redirect both stdout and stderr to the pipe that is read by
		// the parent.
		ret = dup2(pipe[1][1], STDOUT_FILENO);
		if (ret == -1) {
			perror("dup2");
			exit(1);
		}

		ret = dup2(pipe[1][1], STDERR_FILENO);
		if (ret == -1) {
			perror("dup2");
			exit(1);
		}

		// wait for a character from parent
		char c;
		ret = read(pipe[0][0], &c, 1);
		if (ret == 1) {
			close(pipe[0][0]);
			execve(argv[0], newargv, newenviron);
		}
		return -1;
	}

	/* parent */
	printf("%d\n", pid);
	fflush(stdout);

	int err;
	// close pipe fds that we do not need.
	err = close(pipe[0][0]);
	if (err == -1) {
		perror("close");
		exit(1);
	}
	err = close(pipe[1][1]);
	if (err == -1) {
		perror("close");
		exit(1);
	}

	printf("waiting for input in stdin\n");
	fflush(stdout);
	char buff[1024];
	int rd = read(0, buff, sizeof(buff));
	if (rd <= 0) {
		perror("read");
		exit(1);
	}

	// write a single character to child
	printf("waking up child\n");
	write(pipe[0][1], buff, 1);
	close(pipe[0][1]);

	// read messages from child, and print them to stdout.
	for (;;) {
		int rd = read(pipe[1][0], buff, sizeof(buff));
		if (rd == 0) {
			break;
		} else if (rd < 0){
			perror("read");
			exit(1);
		}

		write(1, buff, rd);
	}

	int status;
	wait(&status);
	if (WIFEXITED(status)) {
		printf("child exited with %d\n", WEXITSTATUS(status));
		return 1;
	} else if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		if (sig == expected_sig) {
			printf("child got signal %d. All good.\n", sig);
			return 0;
		}
		printf("child got signal %d, but expecting %d \n", sig, expected_sig);
		fflush(stdout);
		return 1;
	}
}
