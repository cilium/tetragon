#include <stdio.h>
#include <stdlib.h>

#define __naked __attribute__((naked))
#define noinline __attribute__((noinline))

#if defined(__x86_64__)
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
#elif defined(__aarch64__)
int test_1();
__asm__ (
    ".global test_1\n"
    ".type test_1, %function\n"
    "test_1:\n"
  	"stp     x29, x30, [sp, #-16]!\n"
	"mov     x29, sp\n"
	"mov     w0, #0x1\n"
	"mov     w0, #0x3\n"
	"ldp     x29, x30, [sp], #16\n"
	"ret\n"
);
#endif

#if defined(__x86_64__)
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
#elif defined(__aarch64__)
unsigned long test_2();
__asm__ (
    ".global test_2\n"
    ".type test_2, %function\n"
    "test_2:\n"
  	"stp	x29, x30, [sp, #-16]!\n"
	"mov	x29, sp\n"
	"ldr	x0, =0xdeadbeefdeadbeef\n"
	"ldp	x29, x30, [sp], #16\n"
	"ret\n"
);
#endif

int main(int argc, char **argv)
{
	int num;

	if (argc < 2)
		return -1;

	num = atoi(argv[1]);
	if (num == 1)
		return test_1();
	if (num == 2) {
		unsigned long val;

		if (argc != 3)
			return -1;
		val = strtoul(argv[2], NULL, 0);
		return test_2() == val ? 0 : -1;
	}

	return -1;
}
