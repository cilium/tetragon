#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/prctl.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

void sig(int signo)
{
	if (signo == SIGINT)
		kill(0, SIGTERM);
}

int main(int argc, char **argv)
{
	int kick[2];
	char c = 0;
	pid_t p;

	/* Set new process group so kill(0, ...) kills just us and the child. */
	setpgid(0, 0);

	signal(SIGUSR1, sig);
	signal(SIGINT, sig);

	if (pipe(kick)) {
		perror("pipe");
		return -1;
	}

	/* In order to synchronize with our test master we do following:
	 * - create a child and wait for SIGUSR1 signal
	 * - child waits for data in kick pipie
	 * - upon receiving SIGUSR1 parent writes to kick pipe
	 * - and child executes sys_prctl
	 * - both parent and child then hang out in pause waiting for SIGTERM
	 */
	p = fork();
	if (p < 0) {
		perror("fork");
		return -1;
	}

	if (p == 0) {
		/* child waiting for kick pipe from parent */
		read(kick[0], &c, 1);
		prctl(0xdead, 0, 0, 0, 0);
		/* waiting for SIGTERM */
		pause();
	}

	/* waiting for SIGUSR1 */
	pause();
	/* kick child */
	write(kick[1], &c, 1);
	/* waiting for SIGTERM */
	pause();
	return 0;
}
