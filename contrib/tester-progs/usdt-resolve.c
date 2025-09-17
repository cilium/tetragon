//go:build ignore

#include <stdio.h>
#include <stdlib.h>

#include "usdt.h"

struct mystruct {
	unsigned long a, b, c;
};

int main(int argc, char *argv[])
{
	struct mystruct s = {
		.a = rand(),
		.b = 42,
		.c = rand(),
	};


	USDT(tetragon, test, &s);
	printf("p=%p (%lu) a=%lu b=%lu c=%lu\n", &s, (unsigned long)&s, s.a, s.b, s.c);

}
