// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static volatile uint64_t stack_source;

struct stack_frame {
	uint64_t pad0;
	uint64_t pad1;
	uint64_t value;
};

__attribute__((noinline, used)) void stack_slot_barrier(void)
{
	asm volatile("" ::: "memory");
}

__attribute__((noinline, used)) uint64_t stack_slot_value(void)
{
	volatile struct stack_frame frame = {0};
	uint64_t value = stack_source;

	/* Keep value in the same stack slot across an explicit call. */
	frame.value = value;
	stack_slot_barrier();

	return frame.value;
}

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

	stack_source = value;
	printf("%" PRIu64 "\n", stack_slot_value());
	return 0;
}
