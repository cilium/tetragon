//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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
	struct mysubstruct *arr[10];
	struct mysubstruct **dyn;
};

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <field> <val>\n", argv0);
	fprintf(stderr, "field can be one of: v8, v16, v32, v64, sub.v32 arr[idx].v64 dyn[idx].v64\n");
}

// without noinline, the symbol is found, but no event fires
__attribute__((noinline)) int func(int ret, struct mystruct *ms) {
	// without doing something with ms, all the resolved args have
	// value 0, presumably due to optimization
	printf("v64:%lu\n", ms->v64);
	return ret;
}

int main(int argc, char *argv[])
{
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
	} else if ((field[0] == 'a' && field[1] == 'r' && field[2] == 'r')
            || (field[0] == 'd' && field[1] == 'y' && field[2] == 'n')) {
		long idx = atol(&field[4]);
		if (!idx) {
			usage(argv[0]);
			exit(1);
		}
		struct mysubstruct s2 = {
			.v64 = val,
		};
		s.arr[idx] = &s2;
		s.dyn = s.arr;
		printf("sub.v64:%lu\n", s2.v64); // It seems without this line, the compiler make optimization and the test fails.
	} else {
		usage(argv[0]);
		exit(1);
	}

	return func(0, &s);
}
