/*
 * trigger-test-event: trigger a test event on all CPUs
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <inttypes.h>

void setaffinity_oncpu(unsigned int cpu)
{
	cpu_set_t cpu_mask;
	int err;

	CPU_ZERO(&cpu_mask);
	CPU_SET(cpu, &cpu_mask);

	err = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask);
	if (err) {
		perror("sched_setaffinity");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	cpu_set_t mask;
	int err = sched_getaffinity(0, sizeof(cpu_set_t), &mask);
	if (err < 0) {
		perror("sched_getaffinity");
		exit(1);
	}

	unsigned int ncpus = CPU_COUNT(&mask);
	unsigned int cpu_cur = 0;
	printf("ncpus:%d\n", ncpus);
	for (unsigned int i=0; i<ncpus; i++) {
		while (1) {
			unsigned int c = cpu_cur++;
			if (CPU_ISSET(c, &mask)) {
				printf("cpu:%d\n", c);
				setaffinity_oncpu(c);
				syscall(SYS_lseek, (uintptr_t)-1, 0, 4444);
				break;
			}
		}
	}
}
