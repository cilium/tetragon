//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "usdt.h"

struct mysubstruct {
	uint64_t v64;
	uint8_t  v8;
	uint32_t v32;
};

struct mystruct {
	uint8_t  v8;
	uint16_t v16;
	uint32_t v32;
	uint64_t v64;
	struct mysubstruct sub;
};

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <field> <val>\n", argv0);
	fprintf(stderr, "field can be one of: v8, v16, v32, v64, sub.v32\n");
}

int main(int argc, char *argv[])
{
	volatile int ret = 0;
	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	char *field = argv[1];
	long val = atol(argv[2]);
	if (!val) {
		usage(argv[0]);
		exit(1);
	}

	struct mystruct s = {0};
	if (!strcmp(field, "v8")) {
		s.v8 = val;
	} else if (!strcmp(field, "v16")) {
		s.v16 = val;
	} else if (!strcmp(field, "v32")) {
		s.v32 = val;
	} else if (!strcmp(field, "v64")) {
		s.v64 = val;
	} else if (!strcmp(field, "sub.v32")) {
		s.sub.v32 = val;
	} else {
		usage(argv[0]);
		exit(1);
	}

	USDT(tetragon, test, ret, &s);
	printf("ret=%d\n", ret);
	return ret;
}
