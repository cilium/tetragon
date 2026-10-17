#include <stdio.h>
#include "uprobe-big-struct.h"

// Used to test `Override` with `sopath` on a symbol returning a large struct
// by value. The caller passes the address where the result must be written in
// x8 on arm64, which must be preserved like the argument registers.
//
// The override replacement (uprobe_test_lib_big_struct() in uprobe-lib.c)
// returns { x, x + 1, x + 2, x + 3 }. The original function returns all -1,
// so that a missing override is detected.
//
// The function is called twice on the same thread: the first call goes through
// the mmap()/dlopen() state machine, the second one directly jumps to the
// cached symbol.
//
// Exit code:
// * 0: both calls were overridden and returned the expected struct
// * 1: the first call returned a wrong struct
// * 2: the second call returned a wrong struct
// * 3: both calls returned a wrong struct
// * 255: at least one call was not overridden
// A corrupted result address can also crash the process.

#define ARG 10

struct uprobe_test_big_struct
__attribute__((noinline, noipa))
big_struct_ret(long x)
{
	struct uprobe_test_big_struct r = { -1, -1, -1, -1 };

	return r;
}

static int
check(const char *name, struct uprobe_test_big_struct *r)
{
	printf("big_struct_ret() %s call: { %ld, %ld, %ld, %ld }\n", name, r->a, r->b, r->c, r->d);
	return r->a == ARG && r->b == ARG + 1 && r->c == ARG + 2 && r->d == ARG + 3;
}

int
main(void)
{
	struct uprobe_test_big_struct first = { 0 }, second = { 0 };
	int ret = 0;

	first = big_struct_ret(ARG);
	second = big_struct_ret(ARG);

	if (first.a == -1 || second.a == -1)
		return 255;
	if (!check("first", &first))
		ret |= 1;
	if (!check("second", &second))
		ret |= 2;
	return ret;
}
