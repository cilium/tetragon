#include <stdio.h>

// Used to test `Override` with `sopath` on a symbol taking floating-point
// arguments (passed in xmm0-xmm7 on x86_64, v0-v7 on arm64).
//
// The override replacement (uprobe_test_lib_fp_args() in uprobe-lib.c)
// returns a bitmask of the arguments it received with an unexpected value.
// The original function returns -1 so that a missing override is detected.
//
// The function is called twice on the same thread: the first call goes through
// the mmap()/dlopen() state machine, the second one directly jumps to the
// cached symbol.
//
// Exit code:
// * 0: both calls were overridden and received the expected arguments
// * 255: at least one call was not overridden
// * otherwise: bitmask of corrupted arguments (bit N set: argument N corrupted)

int
__attribute__((noinline, noipa))
fp_args(double a0, double a1, double a2, double a3,
	double a4, double a5, double a6, double a7)
{
	return -1;
}

int
main(void)
{
	int first, second;

	first = fp_args(1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5);
	second = fp_args(1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5);
	printf("fp_args() first call: %d, second call: %d\n", first, second);

	if (first < 0 || second < 0)
		return 255;
	return first | second;
}
