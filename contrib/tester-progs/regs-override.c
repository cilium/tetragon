#include <stdio.h>
#include <stdlib.h>

#define __naked __attribute__((naked))
#define noinline __attribute__((noinline))

static __naked int test_1()
{
	asm(
		"push   %rbp\n"
		"mov    %rsp,%rbp\n"
		"mov    $0x1,%eax\n"
		"mov    $0x3,%eax\n"
		"pop    %rbp\n"
		"ret\n"
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
