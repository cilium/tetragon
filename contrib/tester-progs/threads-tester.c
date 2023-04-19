#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <dirent.h>

#define FILENAME "/etc/issue"

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

/* Use direct syscalls and avoid NPTL POSIX standard */
static inline pid_t sys_gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}

void do_open(const char *process, const char *pathname)
{
	FILE *fptr = fopen(pathname, "r");
	if(fptr == NULL)
		errExit("fopen");

	printf("%s\t(pid:%d, tid:%d, ppid:%d)\topen(\"%s\") succeeded\n", process, getpid(), sys_gettid(), getppid(), pathname);
	fclose(fptr);
}

void *thread(void *arg)
{
	do_open("Thread 1:", FILENAME);

	fflush(stdout);
	return 0;
}

void child1()
{
	pthread_t ttid;

	pthread_create(&ttid, NULL, thread, NULL);
	fflush(stdout);
	pthread_join(ttid, NULL);

	do_open("Child 1:", FILENAME);

	fflush(stdout);
}

int main(int argc, char **argv)
{
	pid_t pid;

	printf("parent:\t\t(pid:%d, tid:%d, ppid:%d)\tstarts\n", getpid(), sys_gettid(), getppid());

	if  ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		child1();
		/* child */
		return 0;
	}

	/* wait for child1 to exit */
	int status;
	pid = wait(&status);
	printf("parent:\t\t(pid:%d, tid:%d, ppid:%d)\tchild1 (%d) exited with: %d\n", getpid(), sys_gettid(), getppid(), pid, status);

	return 0;
}
