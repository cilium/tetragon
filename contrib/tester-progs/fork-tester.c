#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>

// NB: global pipe for child 2 to notify parent that it has finished.
int Pipe[2];

// connect to 8.8.8.8:53 (and then close the socket)
void client_run()
{
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		exit(1);
	}

	printf("child 2 (pid:%d, ppid:%d) connecting to 8.8.8.8:53\n", getpid(), getppid());
	long ip8888 =  8 | (8<<8) | (8<<16) | (8<<24);
	struct sockaddr_in srv_addr = {
		.sin_family = AF_INET,
		.sin_addr = {.s_addr = htonl(ip8888)},
		.sin_port = htons(53)
	};
	if (connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == -1) {
		perror("connect");
		exit(1);
	}
	close(fd);
	printf("child 2 done\n");
	return;
}

void child1()
{
	pid_t pid;

	if  ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		for (int i=0; ;i++) {
			int ppid = getppid();
			if (ppid == 1) {
				break;
			}
			if (i == 30) {
				fprintf(stderr, "giving up on waiting our parent to die\n");
				exit(1);
			}
			sleep(1);
		}
		client_run();
	} else {
		/* chilid 1 exits, after creating child 2 */
		printf("child 1 (pid:%d) exits\n", getpid());
		return;
	}

}

void alarm_handler(int signum)
{
	fprintf(stderr, "got an alarm, bailing out\n");
	exit(1);
}

int main(int argc, char **argv)
{
	pid_t pid;

	signal(SIGALRM, alarm_handler);

	printf("parent: (pid:%d, ppid:%d) starts\n", getpid(), getppid());

	if (pipe2(Pipe, O_DIRECT) == -1) {
		perror("pipe2");
		exit(1);
	}

	if  ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		child1();
		/* child */
		return 0;
	}

	if (close(Pipe[1]) == -1) {
		perror("close");
		exit(1);
	}

	/* wait for child1 to exit */
	int status;
	pid = wait(&status);
	printf("parent: (pid:%d) child (%d) exited with: %d\n", getpid(), pid, status);

	/* setup an alarm in case something goes wrong, and wait until the pipe
	 * is closed. This will happen when all children terminate */
	alarm(10);
	char c;
	int ret = read(Pipe[0], &c, 1);
	if (ret < 0) {
		perror("read");
	}

	return 0;
}
