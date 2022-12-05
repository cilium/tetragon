#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

static void *worker(void *ctx)
{
	int cnt = 3;

	while (cnt--) {
		sleep(1);
	}
	return NULL;
}

int main(void)
{
	pthread_t th;
	int err;

	err = pthread_create(&th, NULL, worker, NULL);
	if (err) {
		perror("pthread_create");
		return -1;
	}
	syscall(SYS_exit, 0);
}
