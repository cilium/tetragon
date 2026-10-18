#include <stdio.h>

// Used to test two `Override` actions with `sopath` redirecting two different
// symbols to two different replacements within the same policy.
//
// The policy has one uprobes entry per symbol:
// * first_target() is redirected to uprobe_test_lib_first_target(), returning 1
// * second_target() is redirected to uprobe_test_lib_second_target(), returning 2
// The originals return -1, so that a missing override is detected.
//
// Both functions are called on the same thread, so the second call happens
// after the thread already resolved the first replacement.
//
// Exit code:
// * 0: both calls reached their own replacement
// * 1: first_target() returned a wrong value
// * 2: second_target() returned a wrong value
// * 3: both returned a wrong value
// * 255: at least one call was not overridden

int
__attribute__((noinline, noipa))
first_target(int c)
{
	return -1;
}

int
__attribute__((noinline, noipa))
second_target(int c)
{
	return -1;
}

int
main(void)
{
	int first, second, ret = 0;

	first = first_target(0);
	second = second_target(0);
	printf("first_target() returned %d (expected 1), second_target() returned %d (expected 2)\n",
	       first, second);

	if (first == -1 || second == -1)
		return 255;
	if (first != 1)
		ret |= 1;
	if (second != 2)
		ret |= 2;
	return ret;
}
