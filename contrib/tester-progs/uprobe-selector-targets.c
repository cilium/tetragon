#include <stdio.h>

// Used to test an uprobes entry with two selectors, each with an `Override`
// action redirecting the same symbol to a different replacement loaded from
// sopath. The selectors use matchBinaries, which gives the same result on every
// uprobe hit of the sopath resolution state machine:
// * uprobe-selector-targets-1: uprobe_test_lib_first_target(), returning 1
// * uprobe-selector-targets-2: uprobe_test_lib_second_target(), returning 2
// Both binaries are built from this file and call the traced symbol
// uprobe_test_lib_selector_target() in libuprobe.so, which returns -1, so that a
// missing override is detected.
//
// Each run does a single call, so that the per-thread symbol resolution state
// cannot affect the result.
//
// Exit code: the value returned by the call, 255 if not overridden.

int uprobe_test_lib_selector_target(int c);

int
main(void)
{
	int ret = uprobe_test_lib_selector_target(0);

	printf("uprobe_test_lib_selector_target() returned %d\n", ret);
	return ret == -1 ? 255 : ret;
}
