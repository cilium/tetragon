//go:build ignore

#include <stdio.h>
#include <stdlib.h>

#include "usdt.h"

struct mystruct {
	unsigned long a, b, c;
};

int main(int argc, char *argv[])
{
	volatile int ret = 0;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <int>\n", argv[0]);
		exit(1);
	}
	struct mystruct s = {
		.a = rand(),
		.b = atoi(argv[1]),
		.c = rand(),
	};
	USDT(tetragon, test, ret, &s);
	printf("ret=%d\n", ret);
	return ret;
}
