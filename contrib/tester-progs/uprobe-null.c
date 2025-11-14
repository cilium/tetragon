//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

struct third {
	int32_t val;
};

struct second {
	struct third *third;
};

struct first {
	struct second *second;
};

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <type>\n", argv0);
	fprintf(stderr, "type can be one of: first, second, third, or nonull\n");
}

// without noinline, the symbol is found, but no event fires
__attribute__((noinline)) int func(struct first *first) {
	if (!first || !first->second || !first->second->third)
		return -1;


	printf("%d\n", first->second->third->val);
	return 0;
}

int main(int argc, char *argv[])
{
	struct first first;
	struct second second;
	struct third third;

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	char *type = argv[1];

	if (!strcmp(type, "first")) {
		func(NULL);
	} else if (!strcmp(type, "second")) {
		first.second = NULL;
		func(&first);
	} else if (!strcmp(type, "third")) {
		first.second = &second;
		second.third = NULL;
		func(&first);
	} else if (!strcmp(type, "nonull")) {
		first.second = &second;
		second.third = &third;
		third.val = 0;
		func(&first);
	} else {
		usage(argv[0]);
		exit(1);
	}
	exit(0);
}
