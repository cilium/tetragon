#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

void uprobe_test_lib(void);

// argument test functions
int uprobe_test_lib_arg1(int a1);
int uprobe_test_lib_arg2(char a1, short a2);
int uprobe_test_lib_arg3(unsigned long a1, unsigned int a2, void *a3);
int uprobe_test_lib_arg4(long a1, int a2, char a3, void *a4);
int uprobe_test_lib_arg5(int a1, char a2, unsigned long a3, short a4, void *a5);
int uprobe_test_lib_string_arg(char *str);

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

int main(void)
{
	char *str_arg = "hello world!";

	uprobe_test_lib();
	uprobe_test_lib_arg1(123);
	uprobe_test_lib_arg2('a', 4321);
	uprobe_test_lib_arg3(1, 0xdeadbeef, NULL);
	uprobe_test_lib_arg4(-321, -2, 'b', (void *) 1);
	uprobe_test_lib_arg5(1, 'c', 0xcafe, 1234, (void *) 2);
	uprobe_test_lib_string_arg(pageout(str_arg, strlen(str_arg) + 1));
}
