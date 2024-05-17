// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_FUNC_H__
#define __BPF_FUNC_H__

#ifdef __V61_BPF_PROG
#define FUNC_LOCAL  static __attribute__((noinline)) __attribute__((__unused__))
#define FUNC_INLINE static inline __attribute__((always_inline))
#else
/* Older kernels have all functions inlined.  */
#define FUNC_LOCAL  static inline __attribute__((always_inline))
#define FUNC_INLINE static inline __attribute__((always_inline))
#endif

#endif /* __BPF_FUNC_H__ */
