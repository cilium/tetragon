#define _GNU_SOURCE

#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

int main(int argc, char *argv[])
{
	if (argc <= 1)
		errExit("no target program to execute");

	if (setregid(1879048188, 1879048188) < 0)
		errExit("setregid()");

	if (setreuid(1879048188, 1879048188) < 0)
		errExit("setreuid()");

	execve(argv[1], argv, NULL);
	errExit("execve()");
}
