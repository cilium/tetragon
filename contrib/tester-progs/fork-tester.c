#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define TIMEOUT_SECONDS 30

volatile sig_atomic_t timeout_occurred = 0;

void timeout_handler(int signo)
{
	if (signo == SIGALRM) {
		timeout_occurred = 1;
	}
}

void child2(pid_t reaper_pid)
{
	pid_t initial_ppid = getppid();
	pid_t pid = getpid();

	printf("child 2 (pid:%d, ppid:%d) starts\n", pid, initial_ppid);

	pid_t new_ppid;
	for (int i = 0;; i++) {
		new_ppid = getppid();
		if (new_ppid == reaper_pid) {
			break;
		}
		if (i == 30) {
			fprintf(stderr, "giving up on waiting our parent to die\n");
			exit(EXIT_FAILURE);
		}
		sleep(1);
	}
	printf("child 2 (pid:%d, ppid:%d) exits\n", pid, new_ppid);
}

void child1(pid_t ppid)
{
	pid_t pid;

	if ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		child2(ppid);
	} else {
		/* child 1 exits, after creating child 2 */
		printf("child 1 (pid:%d) exits\n", getpid());
		return;
	}
}

void wait_children(void)
{
	signal(SIGALRM, timeout_handler);
	alarm(TIMEOUT_SECONDS);

	while (1) {
		int status;
		int pid = wait(&status);
		if (pid == -1) {
			if (errno == ECHILD) {
				printf("parent (pid:%d) no more descendants\n", getpid());
				break;
			}
			if (timeout_occurred) {
				fprintf(stderr, "parent (pid:%d) timeout\n", getpid());
				kill(-getpid(), SIGKILL);
				break;
			}
			perror("wait");
		} else {
			printf("parent (pid:%d) child (%d) exited with: %d\n", getpid(), pid,
			       status);
		}
	}
}

int main(void)
{
	pid_t child_pid;
	pid_t pid = getpid();

	printf("parent (pid:%d, ppid:%d) starts\n", pid, getppid());
	prctl(PR_SET_CHILD_SUBREAPER, 1);

	if ((child_pid = fork()) == -1) {
		perror("fork");
		return EXIT_FAILURE;
	} else if (child_pid == 0) {
		child1(pid);
		return EXIT_SUCCESS;
	}

	wait_children();

	return EXIT_SUCCESS;
}
