#include <stdio.h>

// Used to test `Override` with `sopath` on a GCC nested function.
//
// Nested functions access the enclosing function's locals through a pointer
// passed in the static chain register (r10 on x86_64, x18 on arm64). It is a
// hidden argument, so it must be preserved like the regular argument registers.
//
// This file is built twice:
// * as the `uprobe-static-chain` test program, whose nested function is traced;
// * with STATIC_CHAIN_REPLACEMENT defined, as `libuprobe-static-chain.so`,
//   providing the override replacement. Building both from the same source
//   guarantees that the replacement reads `base` through the static chain
//   exactly like the original does.
// GCC emits the nested function as the local symbol `static_chain_target.0`
// in both binaries.
//
// The nested function is called twice on the same thread: the first call goes
// through the mmap()/dlopen() state machine, the second one directly jumps to
// the cached symbol.
//
// Exit code:
// * 0: both calls were overridden and received the right static chain
// * 1: the first call returned a wrong value
// * 2: the second call returned a wrong value
// * 3: both calls returned a wrong value
// * 255: at least one call was not overridden
// A corrupted static chain can also crash the process.

#define BASE 40
#define ARG 2
#define EXPECTED (BASE + ARG)

#ifdef STATIC_CHAIN_REPLACEMENT
#define NOT_OVERRIDDEN_DELTA 0
#else
#define NOT_OVERRIDDEN_DELTA 100
#endif

int
__attribute__((noinline))
static_chain_outer(int *first, int *second)
{
	int base = BASE;

	int __attribute__((noinline)) static_chain_target(int y)
	{
		return base + y + NOT_OVERRIDDEN_DELTA;
	}

	*first = static_chain_target(ARG);
	*second = static_chain_target(ARG);
	return 0;
}

#ifndef STATIC_CHAIN_REPLACEMENT
int
main(void)
{
	int first, second, ret = 0;

	static_chain_outer(&first, &second);
	printf("static_chain_target() first call: %d, second call: %d, expected: %d\n",
	       first, second, EXPECTED);

	if (first == EXPECTED + NOT_OVERRIDDEN_DELTA || second == EXPECTED + NOT_OVERRIDDEN_DELTA)
		return 255;
	if (first != EXPECTED)
		ret |= 1;
	if (second != EXPECTED)
		ret |= 2;
	return ret;
}
#endif