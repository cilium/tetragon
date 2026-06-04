// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#define BLOCKSIZE 4096

int main(int argc, char **argv)
{
	char *avd = "NEW_MESSAGE\n";
	void *buffer;
	int fd;

	if (argc < 2)
		exit(-1);

	fd = open(argv[1], O_WRONLY | O_DIRECT | O_CREAT, S_IRWXU | S_IRWXG);
	if (fd == -1) {
		perror("open");
		exit(-1);
	}

	if (argc == 3) {
	    // Enforce requested fd
	    int target_fd = atoi(argv[2]);
	    // Force temp_fd to be assigned to target_fd
        if (dup2(fd, target_fd) == -1) {
            perror("dup2");
            close(fd);
            exit(-1);
        }
        if (fd != target_fd) {
            close(fd);
        }
        fd = target_fd;
	}

	posix_memalign(&buffer, BLOCKSIZE, BLOCKSIZE);
	memset(buffer, 0, BLOCKSIZE);
	memcpy(buffer, avd, strlen(avd) + 1);

	ssize_t ret = pwrite(fd, buffer, BLOCKSIZE, 0);
	if (ret == -1) {
		perror("write");
		close(fd);
		exit(-1);
	}

	close(fd);
	free(buffer);
	return 0;
}
