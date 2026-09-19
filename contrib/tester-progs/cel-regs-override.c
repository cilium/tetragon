// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noinline __attribute__((noinline))

// Each function will have its own uprobe installed to test a different
// register override
noinline long cel_const(long a, long b, long c)
{
	return a;
}

noinline long cel_one_reg(long a, long b, long c)
{
	return a;
}

noinline long cel_multi_reg(long a, long b, long c)
{
	return a;
}

noinline long cel_bitwise(long a, long b, long c)
{
	return a;
}

noinline long cel_ordering(long a, long b, long c)
{
	return a;
}

static const struct {
	const char *name;
	long (*fn)(long, long, long);
} cases[] = {
	{ "const",      cel_const       },
	{ "one_reg",    cel_one_reg     },
	{ "multi_reg",  cel_multi_reg   },
	{ "bitwise",    cel_bitwise     },
	{ "ordering",   cel_ordering    },
};

static void usage(const char *argv0)
{
	unsigned int i;

	fprintf(stderr, "usage: %s <case> [a] [b] [c]\ncases:", argv0);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		fprintf(stderr, " %s", cases[i].name);
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	long a = 0, b = 0, c = 0, r;
	unsigned int i;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (argc > 2)
		a = strtol(argv[2], NULL, 0);
	if (argc > 3)
		b = strtol(argv[3], NULL, 0);
	if (argc > 4)
		c = strtol(argv[4], NULL, 0);

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (strcmp(argv[1], cases[i].name))
			continue;

		r = cases[i].fn(a, b, c);
		printf("%s(%ld, %ld, %ld) = %ld\n", cases[i].name, a, b, c, r);

		/* exit code carries the result */
		return (int)(r & 0xff);
	}

	usage(argv[0]);
	return 1;
}
