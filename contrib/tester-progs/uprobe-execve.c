#include <stdio.h>
#include <unistd.h>

// Used to test `Override` with `sopath` across execve().
//
// exec_target() is redirected to uprobe_test_lib_pizza() in libuprobe.so,
// returning c + 1. The original returns -1, so that a missing override is
// detected.
//
// The program calls exec_target(1), then re-executes itself on the same thread
// and calls exec_target(1) again in the new image. The symbol resolution state
// is kept per thread, and the thread survives execve(), but the new image has a
// new address space where libuprobe.so is not loaded yet.
//
// Exit code:
// * 0: both calls were overridden
// * 1: the call in the new image was not overridden
// * 254: execve() failed
// * 255: the call in the first image was not overridden

#define EXPECTED 2

int
__attribute__((noinline, noipa))
exec_target(int c)
{
	return -1;
}

int
main(int argc, char *argv[])
{
	int ret = exec_target(1);

	printf("exec_target() returned %d in %s image (expected %d)\n",
	       ret, argc == 1 ? "first" : "new", EXPECTED);
	fflush(stdout);

	if (argc > 1)
		return ret == EXPECTED ? 0 : 1;

	if (ret != EXPECTED)
		return 255;

	char *args[] = { argv[0], "exec", NULL };

	execv("/proc/self/exe", args);
	perror("execv");
	return 254;
}
