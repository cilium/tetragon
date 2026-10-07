// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noinline __attribute__((noinline))

/* Each function will have its own uprobe installed to test a different
 * register override
 */
noinline long cel_multi_reg(long a, long b)
{
	return a * 10 + b;
}

noinline long cel_override_set(long a, long b)
{
	return a + b;
}

static const struct {
	const char *name;
	long (*fn)(long, long);
} cases[] = {
	{ "multi_reg",		cel_multi_reg   },
	{ "override_set",	cel_override_set },
};

static void usage(const char *argv0)
{
	unsigned int i;

	fprintf(stderr, "usage: %s <case> [a] [b]\ncases:", argv0);
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		fprintf(stderr, " %s", cases[i].name);
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	long a = 0, b = 0, r;
	unsigned int i;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (argc > 2)
		a = strtol(argv[2], NULL, 0);
	if (argc > 3)
		b = strtol(argv[3], NULL, 0);

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (strcmp(argv[1], cases[i].name))
			continue;

		r = cases[i].fn(a, b);
		printf("%s(%ld, %ld) = %ld\n", cases[i].name, a, b, r);

		/* exit code carries the result */
		return (int)(r & 0xff);
	}

	usage(argv[0]);
	return 1;
}
