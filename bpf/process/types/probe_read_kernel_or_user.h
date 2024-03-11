// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __PROBE_READ_KERNEL_OR_USER_H__
#define __PROBE_READ_KERNEL_OR_USER_H__

#include "bpf_core_read.h"

#define bpf_probe_read_kernel probe_read_kernel
#define bpf_probe_read_user   probe_read_user

#ifdef __PROBE_KERNEL
static inline __attribute__((always_inline)) int
probe_read_kernel_or_user(void *dst, uint32_t size, const void *src, bool userspace)
{
	if (userspace)
		return probe_read_user(dst, size, src);
	return probe_read_kernel(dst, size, src);
}

static inline __attribute__((always_inline)) int
probe_read_kernel_or_user_masked(void *dst, uint32_t size, uint32_t size_mask, const void *src, bool userspace)
{
	if (userspace) {
		asm volatile("%[size] &= %1;\n"
			     : [size] "+r"(size)
			     : "i"(size_mask));
		return probe_read_user(dst, size, src);
	}
	asm volatile("%[size] &= %1;\n"
		     : [size] "+r"(size)
		     : "i"(size_mask));
	return probe_read_kernel(dst, size, src);
}

static inline __attribute__((always_inline)) int
probe_read_kernel_or_user_str(void *dst, int size, const void *src, bool userspace)
{
	if (userspace)
		return probe_read_user_str(dst, size, src);
	return probe_read_kernel_str(dst, size, src);
}
#else
static inline __attribute__((always_inline)) int
probe_read_kernel_or_user(void *dst, uint32_t size, const void *src, bool userspace)
{
	return probe_read(dst, size, src);
}

static inline __attribute__((always_inline)) int
probe_read_kernel_or_user_masked(void *dst, uint32_t size, uint32_t size_mask, const void *src, bool userspace)
{
	asm volatile("%[size] &= %1;\n"
		     : [size] "+r"(size)
		     : "i"(size_mask));
	return probe_read(dst, size, src);
}

static inline __attribute__((always_inline)) int
probe_read_kernel_or_user_str(void *dst, int size, const void *src, bool userspace)
{
	return probe_read_str(dst, size, src);
}
#endif // __PROBE_KERNEL

/*
 * bpf_core_read_kernel_or_user() abstracts away bpf_probe_read_kernel_or_user() call and captures offset
 * relocation for source address using __builtin_preserve_access_index()
 * built-in, provided by Clang.
 */
#define bpf_core_read_kernel_or_user(userspace, dst, sz, sz_mask, src)                \
	probe_read_kernel_or_user(dst, sz, sz_mask,                                   \
				  (const void *)__builtin_preserve_access_index(src), \
				  userspace)

/*
 * bpf_core_read_kernel_or_user_str() is a thin wrapper around bpf_probe_read_kernel_or_user_str()
 * additionally emitting BPF CO-RE field relocation for specified source
 * argument.
 */
#define bpf_core_read_kernel_or_user_str(userspace, dst, sz, src)                         \
	probe_read_kernel_or_user_str(dst, sz,                                            \
				      (const void *)__builtin_preserve_access_index(src), \
				      userspace)

/*
 * BPF_CORE_READ_KERNEL_OR_USER_INTO() is a more performance-conscious variant of
 * BPF_CORE_READ_KERNEL_OR_USER(), in which final field is read into user-provided storage.
 * See BPF_CORE_READ_KERNEL_OR_USER() below for more details on general usage.
 */
#define BPF_CORE_READ_KERNEL_OR_USER_INTO(userspace, dst, src, a, ...)         \
	({                                                                     \
		typeof(dst) dst_x = dst;                                       \
		typeof(src) src_x = src;                                       \
		typeof(a) a_x = a;                                             \
		((userspace) ? (___core_read(bpf_core_read_user, dst_x,        \
					     src_x, a_x, ##__VA_ARGS__))       \
			     : (___core_read(bpf_core_read, dst_x, src_x, a_x, \
					     ##__VA_ARGS__)))                  \
	})

/*
 * BPF_CORE_READ_KERNEL_OR_USER_STR_INTO() does same "pointer chasing" as
 * BPF_CORE_READ_KERNEL_OR_USER_STR() for intermediate pointers, but then executes (and returns
 * corresponding error code) bpf_core_read_kernel_or_user_str() for final string read.
 */
#define BPF_CORE_READ_KERNEL_OR_USER_STR_INTO(userspace, dst, src, a, ...)                                       \
	({                                                                                                       \
		typeof(dst) dst_x = dst;                                                                         \
		typeof(src) src_x = src;                                                                         \
		typeof(a) a_x = a;                                                                               \
		if (userspace)                                                                                   \
			___core_read(bpf_core_read_user_str, dst_x, src_x,                                       \
				     a_x, ##__VA_ARGS__) else ___core_read(bpf_core_read_str, dst_x, src_x, a_x, \
									   ##__VA_ARGS__)                        \
	})

/*
 * BPF_CORE_READ() is used to simplify BPF CO-RE relocatable read, especially
 * when there are few pointer chasing steps.
 * E.g., what in non-BPF world (or in BPF w/ BCC) would be something like:
 *	int x = s->a.b.c->d.e->f->g;
 * can be succinctly achieved using BPF_CORE_READ as:
 *	int x = BPF_CORE_READ(s, a.b.c, d.e, f, g);
 *
 * BPF_CORE_READ will decompose above statement into 4 bpf_core_read (BPF
 * CO-RE relocatable bpf_probe_read() wrapper) calls, logically equivalent to:
 * 1. const void *__t = s->a.b.c;
 * 2. __t = __t->d.e;
 * 3. __t = __t->f;
 * 4. return __t->g;
 *
 * Equivalence is logical, because there is a heavy type casting/preservation
 * involved, as well as all the reads are happening through bpf_probe_read()
 * calls using __builtin_preserve_access_index() to emit CO-RE relocations.
 *
 * N.B. Only up to 9 "field accessors" are supported, which should be more
 * than enough for any practical purpose.
 */
#define BPF_CORE_READ_KERNEL_OR_USER(userspace, src, a, ...)              \
	({                                                                \
		typeof(src) src_x = src;                                  \
		typeof(a) a_x = a;                                        \
		___type(src_x, a_x, ##__VA_ARGS__) __r;                   \
		BPF_CORE_READ_KERNEL_OR_USER_INTO(userspace, &__r, src_x, \
						  a_x, ##__VA_ARGS__);    \
		__r;                                                      \
	})

#endif // __PROBE_READ_KERNEL_OR_USER_H__
