/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Tetragon */

/*
 * Simplified definitions of the BPF macros that Coccinelle can't parse, see
 * contrib/coccinelle/check.sh. They only need to keep the code parsable.
 */

#define SEC(name) YACFE_ATTRIBUTE
#define FUNC_INLINE static inline
#define FUNC_LOCAL  static
#define __maybe_unused

/* BTF map definitions, see bpf/lib/bpf_helpers.h */
#define __uint(name, val)  int name
#define __type(name, val)  int *name
#define __array(name, val) int *name[]

/* open-coded iterators, see bpf/lib/bpf_helpers.h */
#define bpf_for(i, start, end) YACFE_ITERATOR
#define bpf_repeat(n)          YACFE_ITERATOR
