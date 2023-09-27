#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define gettid() (int) syscall(SYS_gettid)

static void *worker(void *ctx)
{
	fprintf(stderr, "start worker pid=%d tid=%d\n", getpid(), gettid());
	sleep(4);
	fprintf(stderr, "exit worker pid=%d tid=%d\n", getpid(), gettid());
	return NULL;
}

int main(void)
{
	pthread_t th1, th2;
	int err;

	err = pthread_create(&th1, NULL, worker, NULL);
	if (err) {
		perror("pthread_create");
		return -1;
	}
	err = pthread_create(&th2, NULL, worker, NULL);
	if (err) {
		perror("pthread_create");
		return -1;
	}

	fprintf(stderr, "exit main thread  pid=%d tid=%d\n", getpid(), gettid());
	exit(0);
}
