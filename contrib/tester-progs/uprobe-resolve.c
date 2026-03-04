//go:build ignore

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "tester-lib.h"

struct mysubstruct {
	uint64_t v64;
	uint8_t  v8;
	uint32_t v32;
	char     *buff;
};

struct mystruct {
	uint8_t  v8;
	uint16_t v16;
	uint32_t v32;
	uint64_t v64;
	struct mysubstruct sub;
	struct mysubstruct *arr[10];
	struct mysubstruct *dyn;
	struct mysubstruct *subp;
	struct mysubstruct *twodim[5][6];
	uint8_t *v8p;
	char **buffp;
	struct {
		uint8_t foroffsetone;
		union {
			uint16_t anothermember;
			struct {
				uint32_t foroffsettwo;
				int findme;
			};
		};
	};
};

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <field> <val>\n", argv0);
	fprintf(stderr, "field can be one of: v8, v16, v32, v64, sub.v32 arr[idx].v64 dyn[idx].v64, subp.buff, v8p, buffp, findme, twodim[idx][idx]\n");
}

// without noinline, the symbol is found, but no event fires
__attribute__((noinline)) int func(int ret, struct mystruct *ms) {
	// without doing something with ms, all the resolved args have
	// value 0, presumably due to optimization
	printf("v64:%lu\n", ms->v64);
	return ret;
}

bool startsWith(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

int main(int argc, char *argv[])
{
	long val = 0;
	struct mysubstruct ss = {0};
	uint8_t v8;

	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	char *field = argv[1];

	if (strcmp(field, "subp.buff") && strcmp(field, "buffp")) {
		val = atol(argv[2]);
		if (!val) {
			usage(argv[0]);
			exit(1);
		}
	}

	struct mystruct s = {0};
	if (!strcmp(field, "v8")) {
		s.v8 = val;
	} else if (!strcmp(field, "findme")) {
		s.findme = val;
	} else if (!strcmp(field, "v8p")) {
		v8 = val;
		s.v8p = &v8;
	} else if (!strcmp(field, "v16")) {
		s.v16 = val;
	} else if (!strcmp(field, "v32")) {
		s.v32 = val;
	} else if (!strcmp(field, "v64")) {
		s.v64 = val;
	} else if (!strcmp(field, "sub.v32")) {
		s.sub.v32 = val;
	} else if (!strcmp(field, "subp.buff")) {
		ss.buff = argv[2];
		s.subp = pageout(&ss, sizeof(ss));
	} else if (!strcmp(field, "buffp")) {
		s.buffp = &argv[2];
	} else if (startsWith(field, "arr")) {
		long idx = atol(&field[4]);
		if (!idx) {
			usage(argv[0]);
			exit(1);
		}
		struct mysubstruct s2 = {
			.v64 = val,
		};
		s.arr[idx] = &s2;
		printf("sub.v64:%lu\n", s2.v64); // It seems without this line, the compiler make optimization and the test fails.
	} else if (startsWith(field, "dyn")) {
		long idx = atol(&field[4]);
		if (!idx) {
			usage(argv[0]);
			exit(1);
		}

		s.dyn = malloc(sizeof(struct mysubstruct) * (idx + 1));

		if (!s.dyn) {
			fprintf(stderr, "unable to allocate dynamic array\n");
		}
		s.dyn[idx].v64 = val;
	} else if (startsWith(field, "twodim")) {
		long first_idx = atol(&field[7]);
		if (!first_idx) {
			usage(argv[0]);
			exit(1);
		}

		long second_idx = atol(&field[10]);
		if (!second_idx) {
			usage(argv[0]);
			exit(1);
		}

		struct mysubstruct s2 = {
			.v64 = val,
		};
		s.twodim[first_idx][second_idx] = &s2;
		printf("sub.v64:%lu\n", s2.v64); // It seems without this line, the compiler make optimization and the test fails.
	} else {
		usage(argv[0]);
		exit(1);
	}

	return func(0, &s);
}
