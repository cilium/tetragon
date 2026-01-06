/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __VERIFIER_HELPERS_H__
#define __VERIFIER_HELPERS_H__

/*
 * BPF Verifier Bounds Masking Helpers
 *
 * These macros help the BPF verifier understand value bounds by applying
 * bitwise AND masks. The verifier sometimes loses track of bounds during
 * register spilling, complex control flow, or arithmetic operations.
 *
 * Using these macros prevents "unbounded value" errors by explicitly
 * constraining values to known ranges.
 *
 * Usage: VERIFIER_BOUND_12BIT(offset);
 *        // Now verifier knows: 0 <= offset <= 4095
 */

/* 3-bit mask: 0-7 */
#define VERIFIER_BOUND_3BIT(x) \
	asm volatile("%[v] &= 0x7;\n" : [v] "+r"(x))

/* 4-bit mask: 0-15 */
#define VERIFIER_BOUND_4BIT(x) \
	asm volatile("%[v] &= 0xf;\n" : [v] "+r"(x))

/* 5-bit mask: 0-31 */
#define VERIFIER_BOUND_5BIT(x) \
	asm volatile("%[v] &= 0x1f;\n" : [v] "+r"(x))

/* 6-bit mask: 0-63 */
#define VERIFIER_BOUND_6BIT(x) \
	asm volatile("%[v] &= 0x3f;\n" : [v] "+r"(x))

/* 8-bit mask: 0-255 */
#define VERIFIER_BOUND_8BIT(x) \
	asm volatile("%[v] &= 0xff;\n" : [v] "+r"(x))

/* 10-bit mask: 0-1023 */
#define VERIFIER_BOUND_10BIT(x) \
	asm volatile("%[v] &= 0x3ff;\n" : [v] "+r"(x))

/* 11-bit mask: 0-2047 */
#define VERIFIER_BOUND_11BIT(x) \
	asm volatile("%[v] &= 0x7ff;\n" : [v] "+r"(x))

/* 12-bit mask: 0-4095 */
#define VERIFIER_BOUND_12BIT(x) \
	asm volatile("%[v] &= 0xfff;\n" : [v] "+r"(x))

/* 13-bit mask: 0-8191 */
#define VERIFIER_BOUND_13BIT(x) \
	asm volatile("%[v] &= 0x1fff;\n" : [v] "+r"(x))

/* 14-bit mask: 0-16383 */
#define VERIFIER_BOUND_14BIT(x) \
	asm volatile("%[v] &= 0x3fff;\n" : [v] "+r"(x))

/* 15-bit mask: 0-32767 */
#define VERIFIER_BOUND_15BIT(x) \
	asm volatile("%[v] &= 0x7fff;\n" : [v] "+r"(x))

/* 16-bit mask: 0-65535 */
#define VERIFIER_BOUND_16BIT(x) \
	asm volatile("%[v] &= 0xffff;\n" : [v] "+r"(x))

/* 32-bit mask: Reminds verifier value is 32-bit */
#define VERIFIER_BOUND_32BIT(x) \
	asm volatile("%[v] &= 0xffffffff;\n" : [v] "+r"(x))

#endif /* __VERIFIER_HELPERS_H__ */
