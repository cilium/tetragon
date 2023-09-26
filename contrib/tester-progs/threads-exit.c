#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

static int goo;

static void *worker(void *ctx)
{
	int ready_out = (intptr_t) ctx;

	write(ready_out, "R", 1);

	while (!goo) {}
	syscall(SYS_exit, 0);
	return NULL;
}

int main(void)
{
	int ncpus = get_nprocs(), nthreads = ncpus * 10;
	int i, err, readyfds[2];
	pthread_t th[nthreads];
	cpu_set_t set;
	char dummy;

	/* make sure we can run on all cpus */
	CPU_ZERO(&set);
	for (i = 0; i < ncpus; i++)
		CPU_SET(i, &set);
	if (sched_setaffinity(0, sizeof(set), &set) == -1) {
		perror("sched_setaffinity");
		return -1;
	}


	if (pipe(readyfds)) {
		perror("pipe");
		return -1;
	}

	/* print out group leader for test checker */
	printf("TGID %d\n", getpid());
	fflush(NULL);

	for (i = 0; i < nthreads; i++) {
		err = pthread_create(&th[i], NULL, worker, (void*)(intptr_t) readyfds[1]);
		if (err) {
			perror("pthread_create");
			return -1;
		}
	}

	/* Make sure all threads started.. */
	for (i = 0; i < nthreads; i++) {
		if (read(readyfds[0], &dummy, 1) != 1) {
			perror("read");
			return -1;
		}
	}

	/* .. and then tell threads to exit */
	goo = 1;
	syscall(SYS_exit, 0);
}
