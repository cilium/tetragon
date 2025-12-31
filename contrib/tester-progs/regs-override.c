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

static __naked unsigned long test_2()
{
	asm(
		"push   %rbp\n"                        /* +0  55                            */
		"mov    %rsp,%rbp\n"                   /* +1  48 89 e5                      */
		"mov    $0xdeadbeefdeadbeef,%rax\n"    /* +4  48 b8 00 00 00 00 ef be ad de */
		"pop    %rbp\n"                        /* +14 5d                            */
		"ret\n"                                /* +15 c3                            */
	);
}

static const char *test_3_string = "test_3_string";

static __naked unsigned long test_3()
{
	asm volatile (
		"push   %%rbp\n"                       /* +0  55                            */
		"mov    %%rsp, %%rbp\n"                /* +1  48 89 e5                      */
		"mov    %[str], %%rdi\n"               /* +4  48 8b 3d 96 2e 00 00          */
		"pop    %%rbp\n"                       /* +11 5d                            */
		"mov    $0x0,%%rax\n"                  /* +12 48 c7 c0 00 00 00 00          */
		"mov    $0xff,%%rax\n"                 /* +19 48 c7 c0 ff 00 00 00          */
		"ret\n"                                /* +26 c3                            */
		:
		: [str] "m" (test_3_string)
	);
}

int main(int argc, char **argv)
{
	unsigned long val;
	int num;

	if (argc < 2)
		return -1;

	num = atoi(argv[1]);
	switch (num) {
	case 1:
		return test_1();
	case 2:
		if (argc != 3)
			return -1;
		val = strtoul(argv[2], NULL, 0);
		return test_2() == val ? 0 : -1;
	case 3:
		return test_3();
	}

	return -1;
}
