// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static volatile uint64_t stack_source;

struct mysubstruct {
	uint64_t empty;
	uint64_t arr[10];
};

struct mystruct {
	struct mysubstruct *sub;
};

#if defined(__x86_64__) || defined(__amd64__)
__attribute__((noinline, used, naked)) uint64_t mov_in_rsp(struct mystruct *ms)
{
	asm volatile (
		"push   %rdi\n"            /* rsp -= 8, (rsp) = ms; return addr preserved */
		"mov    (%rsp), %rax\n"    /* rax = ms */
		"pop    %rdi\n"            /* rsp += 8; return addr back on top */
		"ret\n"
	);
}
#elif defined(__aarch64__)
__attribute__((noinline, used, naked)) uint64_t mov_in_rsp(struct mystruct *ms)
{
	asm volatile (
		"str    x0, [sp, #-16]!\n"   /* sp -= 16, [sp] = ms; lr holds return addr */
		"ldr    x0, [sp]\n"          /* x0 = ms */
		"add    sp, sp, #16\n"       /* sp += 16 */
		"ret\n"
	);
}
#else
__attribute__((noinline, used)) uint64_t mov_in_rsp(struct mystruct *ms)
{
	return (uint64_t)ms;
}
#endif

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <value>\n", argv0);
}

int main(int argc, char *argv[])
{
	char *endptr = NULL;
	uint64_t value;

	if (argc != 2) {
		usage(argv[0]);
		exit(1);
	}

	value = strtoull(argv[1], &endptr, 10);
	if (*endptr != '\0') {
		usage(argv[0]);
		exit(1);
	}

	struct mystruct ms = {};
	ms.sub = malloc(sizeof(struct mysubstruct));
	ms.sub->arr[8] = value;
	stack_source = value;
	printf("%" PRIu64 "\n", mov_in_rsp(&ms));
	free(ms.sub);
	return 0;
}
