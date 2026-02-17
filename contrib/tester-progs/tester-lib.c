#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* Page out a memory region containing 'data' of length 'len'.
 * Returns the address of the paged-out region.
 * The temp file backing is used to work around the fact that our test VMs
 * don't have any disk backed storage to use for swap.
 */
void *pageout(void *data, size_t len) {
	char template[] = "/tmp/pageout-XXXXXX";

	/* 1. Create temp file */
	int fd = mkstemp(template);
	if (fd < 0) {
		perror("mkstemp");
		return NULL;
	}

	unlink(template); /* auto-delete */

	/* 2. Ensure file size matches the data size */
	if (ftruncate(fd, len) < 0) {
		perror("ftruncate");
		return NULL;
	}

	/* 3. mmap file */
	char *p = mmap(NULL, len,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	/* 4. Copy the data to memory mapped region */
	memcpy(p, data, len);

	/* 5. Force page out */
	if (madvise(p, len, MADV_PAGEOUT) < 0) {
		if (errno != EINVAL) {
			// MADV_PAGEOUT was introduced in kernel 5.10 and backported to 5.4
			// It's not available in our 4.19 test kernel, so ignore EINVAL errors
			perror("madvise(MADV_PAGEOUT)");
			return NULL;
		}
	}
	return p;
}
