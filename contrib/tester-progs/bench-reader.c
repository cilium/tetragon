
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <time.h>

struct thread_arg {
	int id;
	int cpu;
	int fd;
	size_t io_size;
	useconds_t nsleep;
};

void *
reader(void *arg_)
{
	struct thread_arg *arg = (struct thread_arg *)arg_;

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(arg->cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) == -1) {
		perror("sched_setaffinity");
		exit(1);
	}

	printf("start thread %d (cpu:%d)\n", arg->id, arg->cpu);
	char buff[arg->io_size];
	for (;;) {
		read(arg->fd, buff, sizeof(buff));
		if (arg->nsleep) {
			const struct timespec req = {
				.tv_nsec = arg->nsleep,
			};

			nanosleep(&req, NULL);
		}
	}
	return NULL;
}

void
usage(char *prog)
{
	fprintf(stderr, "Usage: %s [-t <nthreads>] [-w wait] [-s nsleep]\n", prog);
}

int
main(int argc, char **argv)
{

	int zero_fd;
	int wait_time = 60*10, nthreads, opt, ncpus, io_size = 10;
	useconds_t thread_nsleep = 100;

	ncpus = get_nprocs();
	nthreads = ncpus;

	while ((opt = getopt(argc, argv, "t:s:w:i:")) != -1) {
		switch (opt) {
			case 't':
				nthreads = atoi(optarg);
				break;
			case 'w':
				wait_time = atoi(optarg);
				break;
			case 's':
				thread_nsleep = atoi(optarg);
				break;
			case 'i':
				io_size = atoi(optarg);
				break;
			default: /* '?' */
				usage(argv[0]);
				exit(1);
		}
	}

	printf("nthreads=%d wait_time=%d thread_nsleep=%d io_size=%d\n", nthreads, wait_time, thread_nsleep, io_size);
	zero_fd = open("/dev/zero", O_RDONLY);
	if (zero_fd < 0) {
		perror("open");
		exit(1);
	}

	pthread_t tids[nthreads];
	struct thread_arg args[nthreads];

	for (int i = 0; i < nthreads; i++) {
		struct thread_arg *arg = &args[i];
		arg->fd = zero_fd;
		arg->nsleep = thread_nsleep;
		arg->io_size = io_size;
		arg->id = i;
		arg->cpu = i % ncpus;
		pthread_create(&tids[i], NULL, reader, arg);
	}

	sleep(wait_time);
}
