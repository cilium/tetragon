#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define gettid() (int) syscall(SYS_gettid)

static void *worker(void *ctx)
{
	unsigned long cnt = (unsigned long) ctx;
	pthread_t th;
	int err;

	fprintf(stderr, "worker %d:%d cnt %lu\n", getpid(), gettid(), cnt);

	if (cnt == 2 || cnt == 4) {
		err = pthread_create(&th, NULL, worker, (void *) (cnt + 1));
		if (err) {
			perror("pthread_create");
			return NULL;
		}
	}

	while (cnt--) {
		sleep(1);
	}

	fprintf(stderr, "exit %d:%d\n", getpid(), gettid());
	return NULL;
}

int main(void)
{
	pthread_t th;
	int err;

	err = pthread_create(&th, NULL, worker, (void *) 2);
	if (err) {
		perror("pthread_create");
		return -1;
	}
	err = pthread_create(&th, NULL, worker, (void *) 4);
	if (err) {
		perror("pthread_create");
		return -1;
	}

	sleep(3);
	fprintf(stderr, "exit %d:%d\n", getpid(), gettid());
	syscall(SYS_exit, 0);
}
