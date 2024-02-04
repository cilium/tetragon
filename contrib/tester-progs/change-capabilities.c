// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/capability.h>

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

int check_cap(cap_value_t cap)
{
	int ret;
	cap_t caps;
	cap_flag_value_t value = 0;

	caps = cap_get_proc();
	if (caps == NULL)
		errExit("cap_get_proc");

	ret = cap_get_flag(caps, cap, CAP_EFFECTIVE, &value);
	if (ret)
		errExit("cap_get_flag");

	cap_free(caps);

	return value;
}

void clear_cap(cap_value_t c)
{
	cap_t cap;
	cap_value_t cap_list[CAP_LAST_CAP+1];

	cap = cap_get_proc();
	if (cap == NULL)
		errExit("cap_get_proc");

	cap_list[0] = c;
	if (cap_set_flag(cap, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR) == -1)
		errExit("cap_set_flag");

	if (cap_set_proc(cap) == -1)
		errExit("cap_set_proc");

	cap_free(cap);
}

void set_cap(cap_value_t c)
{
	cap_t cap;
	cap_value_t cap_list[CAP_LAST_CAP+1];

	cap = cap_get_proc();
	if (cap == NULL)
		errExit("cap_get_proc");

	cap_list[0] = c;
	if (cap_set_flag(cap, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1)
		errExit("cap_set_flag");

	if (cap_set_proc(cap) == -1)
		errExit("cap_set_proc");

	cap_free(cap);
}

int main(int argc, char *argv[])
{
	pid_t pid = getpid();
	int cap;

	cap = check_cap(CAP_SYS_ADMIN);
	if (cap) {
		printf("(pid:%d) checking capability CAP_SYS_ADMIN: is set\n", pid);
		printf("(pid:%d) clearing capability CAP_SYS_ADMIN and CAP_CHOWN\n", pid);
		clear_cap(CAP_SYS_ADMIN);
		clear_cap(CAP_CHOWN);
	} else {
		printf("checking capability CAP_SYS_ADMIN: not set\n");
		return 0;
	}

	printf("(pid:%d) restoring capability CAP_SYS_ADMIN and CAP_CHOWN\n", pid);
	set_cap(CAP_SYS_ADMIN);
	set_cap(CAP_CHOWN);

	fflush(stdout);
	return 0;
}
