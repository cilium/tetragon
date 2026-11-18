// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_COMPILER_H__
#define __BPF_COMPILER_H__

/* Generic multi-kprobes require kernel 5.18 or newer, including when using
 * an older object variant. They can use BPF subprograms with tail calls.
 */
#if defined(__V61_BPF_PROG) || \
	(defined(__MULTI_KPROBE) && (defined(GENERIC_KPROBE) || defined(GENERIC_KRETPROBE)))
#define FUNC_LOCAL  static __attribute__((noinline)) __attribute__((__unused__))
#define FUNC_INLINE static inline __attribute__((always_inline))
#else
/* Programs that can run on older kernels keep all functions inlined. */
#define FUNC_LOCAL  static inline __attribute__((always_inline))
#define FUNC_INLINE static inline __attribute__((always_inline))
#endif

#ifndef fallthrough
#define fallthrough __attribute__((fallthrough))
#endif

#ifndef __throw_build_bug
#define __throw_build_bug() __builtin_trap()
#endif

#ifndef __nobuiltin
#define __nobuiltin(X) __attribute__((no_builtin(X)))
#endif

#endif /* __BPF_COMPILER_H__ */
