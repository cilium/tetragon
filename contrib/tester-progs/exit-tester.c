#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
static inline pid_t gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}
#endif

// is_zombie reads /proc/<pid>/stat, and returns true if status is Z (zombie)
bool is_zombie(int pid) {
	const int buff_size = 128;
	char fmt[] = "/proc/%d/stat";
	char buff[buff_size];
	if (snprintf(buff, buff_size, fmt, pid) >= 128) {
		fprintf(stderr, "snprintf failed\n");
		exit(1);
	}
	FILE *stat = fopen(buff, "r");
	char comm[16 /* TASK_COMM_LEN */], state;
	fscanf(stat, "%d %s %c", &pid, comm, &state);
	fclose(stat);
	printf("status: pid=%d comm=%s state=%c\n", pid, comm, state);
	return state == 'Z';
}

// thread will wait until parent is in zombie state, and then exec /bin/echo
void *thread(void *arg)
{
	int pid = getpid();
	printf("thread: pid:%d tid:%d\n", pid, gettid());
	fflush(stdout);
	for (;;) {
		printf("check if parent is in zombie state...\n");
		fflush(stdout);
		if (is_zombie(pid)) {
			break;
		}
		printf("nope, sleeping\n");
		fflush(stdout);
		sleep(1);
	}
	printf("parent died\n");
	fflush(stdout);
	char *argv[] = {"/bin/sh", "-c", "echo pizza is the best!", NULL};
	if (execve("/bin/sh", argv, NULL) == -1) {
		perror("exec");
		exit(1);
	}
	return 0;
}

// spawn a thread, and then pthread_exit() so that whole process group is not killed
int main(int argc, char **argv)
{
	pthread_t tid;
	pthread_create(&tid, NULL, thread, NULL);
	printf("main: pid:%d tid:%d, thread:%ld\n", getpid(), gettid(), tid);
	fflush(stdout);
	int ret = 0;
	pthread_exit(&ret);
}
