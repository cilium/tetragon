#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/wait.h>
#include <signal.h>

void sig(int signo)
{
	kill(0, SIGTERM);
	waitpid(-1, NULL, 0);
}

int main(int argc, char **argv)
{
	long i, count = 10;


	if (argc == 2) {
		count = strtol(argv[1], NULL, 10);
		if (count == LONG_MIN)
			return -1;
	}

	printf("forking %ld\n", count);

	/* Set new process group so kill(0, ...) works properly. */
	setpgid(0, 0);

	/* We expect SIGINT to trigger the kill for all spawned processes. */
	signal(SIGINT, sig);

	for (i = 1; i < count; i++) {
		pid_t p = fork();

		if (p < 0) {
			perror("fork");
			return -1;
		}

		if (p == 0) {
			pause();
			exit(0);
		}
	}

	pause();
	return 0;
}
