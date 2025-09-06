//go:build ignore
#include <linux/types.h>
#include <stdio.h>
#include "usdt.h"
#include "sdt.h"

static volatile int idx = 2;
static volatile short nums[] = {-1, -2, -3, -4};
static unsigned long bla = 0xdeadbeef;

static volatile struct {
        int x;
        signed char y;
} t1 = { 1, -127 };

/* SIB related code borrowed from kernel's bpf/selftests. */

#define SEC(name) __attribute__((section(name), used))

#if defined(__x86_64__) || defined(__i386__)
/*
 * SIB (Scale-Index-Base) addressing format: "size@(base_reg, index_reg, scale)"
 * - 'size' is the size in bytes of the array element, and its sign indicates
 *   whether the type is signed (negative) or unsigned (positive).
 * - 'base_reg' is the register holding the base address, normally rdx or edx
 * - 'index_reg' is the register holding the index, normally rax or eax
 * - 'scale' is the scaling factor (typically 1, 2, 4, or 8), which matches the
 *    size of the element type.
 *
 * For example, for an array of 'short' (signed 2-byte elements), the SIB spec would be:
 * - size: -2 (negative because 'short' is signed)
 * - scale: 2 (since sizeof(short) == 2)
 *
 * The resulting SIB format: "-2@(%%rdx,%%rax,2)" for x86_64, "-2@(%%edx,%%eax,2)" for i386
 */
static volatile short array[] = {-1, -2, -3, -4};

#if defined(__x86_64__)
#define USDT_SIB_ARG_SPEC -2@(%%rdx,%%rax,2)
#else
#define USDT_SIB_ARG_SPEC -2@(%%edx,%%eax,2)
#endif

unsigned short test_usdt_sib_semaphore SEC(".probes");

static void trigger_sib_spec(void)
{
	/*
	 * Force SIB addressing with inline assembly.
	 *
	 * You must compile with -std=gnu99 or -std=c99 to use the
	 * STAP_PROBE_ASM macro.
	 *
	 * The STAP_PROBE_ASM macro generates a quoted string that gets
	 * inserted between the surrounding assembly instructions. In this
	 * case, USDT_SIB_ARG_SPEC is embedded directly into the instruction
	 * stream, creating a probe point between the asm statement boundaries.
	 * It works fine with gcc/clang.
	 *
	 * Register constraints:
	 * - "d"(array): Binds the 'array' variable to %rdx or %edx register
	 * - "a"(0): Binds the constant 2 to %rax or %eax register
	 * These ensure that when USDT_SIB_ARG_SPEC references %%rdx(%edx) and
	 * %%rax(%eax), they contain the expected values for SIB addressing.
	 *
	 * The "memory" clobber prevents the compiler from reordering memory
	 * accesses around the probe point, ensuring that the probe behavior
	 * is predictable and consistent.
	 */
	asm volatile(
		STAP_PROBE_ASM(test, usdt_sib, USDT_SIB_ARG_SPEC)
		:
		: "d"(array), "a"(2)
		: "memory"
	);
}
#else
static void trigger_sib_spec(void) { }
#endif

static void __always_inline trigger_func(void) {
	long y = 42;
	int x = 1;

	if (USDT_IS_ACTIVE(test, usdt0))
		USDT_WITH_SEMA(test, usdt0);
	if (USDT_IS_ACTIVE(test, usdt3))
		USDT_WITH_SEMA(test, usdt3, x, y, bla);
	if (USDT_IS_ACTIVE(test, usdt12)) {
		USDT_WITH_SEMA(test, usdt12,
			     x, x + 1, y, x + y, 5,
			     y / 7, bla, bla + 8, -9, nums[x],
			     nums[idx], t1.y);
	}

	trigger_sib_spec();
}

int main(int argc, char **argv)
{
	trigger_func();
	return 0;
}
