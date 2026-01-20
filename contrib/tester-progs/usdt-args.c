//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "usdt.h"

#define PAGE_ALIGN(addr, page_size) ((addr) & ~(page_size - 1))

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <type> <val>\n", argv0);
	fprintf(stderr, "type can be one of: string\n");
}

/* Page out a memory region containing 'data' of length 'len'.
 * Returns the address of the paged-out region.
 * The temp file backing is used to work around the fact that our test VMs
 * don't have any disk backed storage to use for swap.
 */
void *pageout(void *data, size_t len) {
	const size_t page_size = sysconf(_SC_PAGESIZE);
	char template[] = "/tmp/pageout-XXXXXX";

	/* 1. Create temp file */
	int fd = mkstemp(template);
	if (fd < 0) {
		perror("mkstemp");
		exit(1);
	}

	unlink(template); /* auto-delete */

	/* 2. Ensure file is one page */
	if (ftruncate(fd, page_size) < 0) {
		perror("ftruncate");
		exit(1);
	}

	/* 3. mmap file */
	char *p = mmap(NULL, page_size,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	/* 4. Touch the page (page-in) */
	memcpy(p, data, len);

	/* 5. Force page out */
	if (madvise(p, page_size, MADV_PAGEOUT) < 0) {
		if (errno != EINVAL) {
			// MADV_PAGEOUT was introduced in kernel 5.10 and backported to 5.4
			// It's not available in our 4.19 test kernel, so ignore EINVAL errors
			perror("madvise(MADV_PAGEOUT)");
			exit(1);
		}
	}
	return p;
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	char *type = argv[1];
	if (!strcmp(type, "string")) {
		void *paged_data = pageout(argv[2], strlen(argv[2]) + 1);
		USDT(tetragon, string_test, paged_data);
	} else {
		usage(argv[0]);
		exit(1);
	}
}
