//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "usdt.h"
#include "tester-lib.h"

#define PAGE_ALIGN(addr, page_size) ((addr) & ~(page_size - 1))

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <type> <val>\n", argv0);
	fprintf(stderr, "type can be one of: string\n");
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
