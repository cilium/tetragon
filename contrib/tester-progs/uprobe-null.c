//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

struct mysubstruct {
	int32_t val;
};

struct mystruct {
	struct mysubstruct *subp;
};

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <type>\n", argv0);
	fprintf(stderr, "type can be one of: first, middle, nonull\n");
}

// without noinline, the symbol is found, but no event fires
__attribute__((noinline)) int func(struct mystruct *ms) {
	if (!ms)
		return -1;

	if (!ms->subp)
		return -1;

	printf("%d\n", ms->subp->val);
	return 0;
}

int main(int argc, char *argv[])
{

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	char *type = argv[1];

	if (!strcmp(type, "first")) {
		func(NULL);
	} else if (!strcmp(type, "middle")) {
		struct mystruct ms;
		ms.subp = NULL;
		func(&ms);
	} else if (!strcmp(type, "nonull")) {
		struct mystruct ms;
		struct mysubstruct mss;
		ms.subp = &mss;
		mss.val = 0;
		func(&ms);
	} else {
		usage(argv[0]);
		exit(1);
	}
	exit(0);
}
