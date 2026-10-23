#include <stdio.h>
#include <stdlib.h>

// Used to test an uprobes entry with two selectors matching the first argument
// of arg_target(), each redirecting the call to a replacement loaded from a
// different sopath:
// * arg0 == 1: uprobe_test_lib_arg_target() in libuprobe-arg-target-1.so, returning 1
// * arg0 == 2: uprobe_test_lib_arg_target() in libuprobe-arg-target-2.so, returning 2
// The original returns -1, so that a missing override is detected.
//
// Usage:
// * uprobe-arg-targets <1|2>: single call with the given argument, the exit
//   code is the returned value (255 if not overridden);
// * uprobe-arg-targets: arg_target(1) then arg_target(2) on the same thread,
//   the exit code is 10 * first + second (255 if a call was not overridden):
//   12 when each call reaches its own replacement.

int
__attribute__((noinline, noipa))
arg_target(int c)
{
	return -1;
}

int
main(int argc, char *argv[])
{
	int first, first_2, second, second_2;

	if (argc == 2) {
		int arg = (int)strtol(argv[1], NULL, 10);

		first = arg_target(arg);
		printf("arg_target(%d) returned %d\n", arg, first);
		return first == -1 ? 255 : first;
	}

	first = arg_target(1);
	second = arg_target(2);
	printf("arg_target(1) returned %d (expected 1), arg_target(2) returned %d (expected 2)\n",
	       first, second);
    first_2 = arg_target(1);
    second_2 = arg_target(2);
    printf("arg_target(1) returned %d (expected 1), arg_target(2) returned %d (expected 2)\n",
           first_2, second_2);

	if (first == -1 || second == -1 || first_2 == -1 || second_2 == -1)
		return 255;
	return 10 * (first + first_2) + second + second_2;
}