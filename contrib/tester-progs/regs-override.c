#include <stdio.h>
#include <stdlib.h>

#define __naked __attribute__((naked))
#define noinline __attribute__((noinline))

static __naked int test_1()
{
	asm(
		"push   %rbp\n"         /* +0  55             */
		"mov    %rsp,%rbp\n"    /* +1  48 89 e5       */
		"mov    $0x1,%eax\n"    /* +4  b8 01 00 00 00 */
		"mov    $0x3,%eax\n"    /* +9  b8 03 00 00 00 */
		"pop    %rbp\n"         /* +14 5d             */
		"ret\n"                 /* +15 c3             */
	);
}

int main(int argc, char **argv)
{
	int num;

	if (argc != 2)
		return -1;

	num = atoi(argv[1]);
	if (num == 1)
		return test_1();

	return -1;
}
