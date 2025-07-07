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

	/* Set new process group so kill(0, ...) works properly. */
	setpgid(0, 0);
	signal(SIGUSR1, sig);
	signal(SIGINT, sig);

	if (pipe(kick)) {
		perror("pipe");
		return -1;
	}

	p = fork();
	if (p < 0) {
		perror("fork");
		return -1;
	}

	if (p == 0) {
		read(kick[0], &c, 1);
		prctl(0xdead, 0, 0, 0, 0);
		pause();
	}

	pause();
	write(kick[1], &c, 1);
	pause();
	return 0;
}
