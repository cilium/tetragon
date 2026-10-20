#include <stdio.h>

// Override replacement for arg_target() in uprobe-arg-targets.c, built as
// libuprobe-arg-target-<TARGET_VALUE>.so, one per selector.

int uprobe_test_lib_arg_target(int c)
{
	printf("uprobe_test_lib_arg_target from library %d called\n", TARGET_VALUE);
	return TARGET_VALUE;
}
