// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_HELPERS_
#define __BPF_HELPERS_

#include "api.h"
#include "compiler.h"

#ifndef PATH_MAP_SIZE
#define PATH_MAP_SIZE 4096
#endif

#ifndef __READ_ONCE
#define __READ_ONCE(x) (*(volatile typeof(x) *)&x)
#endif
#ifndef __WRITE_ONCE
#define __WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)
#endif

#ifndef READ_ONCE
#define READ_ONCE(x)                    \
	({                              \
		typeof(x) __val;        \
		__val = __READ_ONCE(x); \
		compiler_barrier();     \
		__val;                  \
	})
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v)                \
	({                              \
		typeof(x) __val = (v);  \
		__WRITE_ONCE(x, __val); \
		compiler_barrier();     \
		__val;                  \
	})
#endif

#define XSTR(s) STR(s)
#define STR(s)	#s

/*
 * Following define is to assist VSCode Intellisense so that it treats
 * __builtin_preserve_access_index() as a const void * instead of a
 * simple void (because it doesn't have a definition for it). This stops
 * Intellisense marking all _(P) macros (used in probe_read()) as errors.
 * To use this, just define VSCODE in 'C/C++: Edit Configurations (JSON)'
 * in the Command Palette in VSCODE (F1 or View->Command Palette...):
 *    "defines": ["VSCODE"]
 * under configurations.
 */
#ifdef VSCODE
const void *__builtin_preserve_access_index(void *);
#endif
#define _(P) (__builtin_preserve_access_index(P))

/*
 * Convenience macro to check that field actually exists in target kernel's.
 * Returns:
 *    1, if matching field is present in target kernel;
 *    0, if no matching field found.
 */
#define bpf_core_field_exists(field) \
	__builtin_preserve_field_info(field, BPF_FIELD_EXISTS)

/* second argument to __builtin_preserve_enum_value() built-in */
enum bpf_enum_value_kind {
	BPF_ENUMVAL_EXISTS = 0, /* enum value existence in kernel */
	BPF_ENUMVAL_VALUE = 1, /* enum value value relocation */
};

#include "bpf_core_read.h"

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits.
 */
FUNC_INLINE void relax_verifier(void)
{
	/* Calling get_smp_processor_id() in asm saves an instruction as we
	 * don't have to store the result to ensure the call takes place.
	 * However, we have to specifiy the call target by number and not
	 * name, hence 'call 8'. This is unlikely to change, though, so this
	 * isn't a big issue.
	 */
	asm volatile("call 8;\n" ::
			     : "r0", "r1", "r2", "r3", "r4", "r5");
}

FUNC_INLINE void compiler_barrier(void)
{
	asm volatile("" ::
			     : "memory");
}

#define __uint(name, val)  int(*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define SEC(name) __attribute__((section(name), used))

/*
 * Helper macros to manipulate data structures
 */

/* offsetof() definition that uses __builtin_offset() might not preserve field
 * offset CO-RE relocation properly, so force-redefine offsetof() using
 * old-school approach which works with CO-RE correctly
 */
#undef offsetof
#define offsetof(type, member) ((unsigned long)&((type *)0)->member)

/* redefined container_of() to ensure we use the above offsetof() macro */
#undef container_of
#define container_of(ptr, type, member)                      \
	({                                                   \
		void *__mptr = (void *)(ptr);                \
		((type *)(__mptr - offsetof(type, member))); \
	})

#ifdef __V612_BPF_PROG
#ifndef bpf_for_each
/* bpf_for_each(iter_type, cur_elem, args...) provides generic construct for
 * using BPF open-coded iterators without having to write mundane explicit
 * low-level loop logic. Instead, it provides for()-like generic construct
 * that can be used pretty naturally. E.g., for some hypothetical cgroup
 * iterator, you'd write:
 *
 * struct cgroup *cg, *parent_cg = <...>;
 *
 * bpf_for_each(cgroup, cg, parent_cg, CG_ITER_CHILDREN) {
 *     bpf_printk("Child cgroup id = %d", cg->cgroup_id);
 *     if (cg->cgroup_id == 123)
 *         break;
 * }
 *
 * I.e., it looks almost like high-level for each loop in other languages,
 * supports continue/break, and is verifiable by BPF verifier.
 *
 * For iterating integers, the difference between bpf_for_each(num, i, N, M)
 * and bpf_for(i, N, M) is in that bpf_for() provides additional proof to
 * verifier that i is in [N, M) range, and in bpf_for_each() case i is `int
 * *`, not just `int`. So for integers bpf_for() is more convenient.
 *
 * Note: this macro relies on C99 feature of allowing to declare variables
 * inside for() loop, bound to for() loop lifetime. It also utilizes GCC
 * extension: __attribute__((cleanup(<func>))), supported by both GCC and
 * Clang.
 */
#define bpf_for_each(type, cur, args...) for (							\
	/* initialize and define destructor */							\
	struct bpf_iter_##type ___it __attribute__((aligned(8), /* enforce, just in case */,	\
						    cleanup(bpf_iter_##type##_destroy))),	\
	/* ___p pointer is just to call bpf_iter_##type##_new() *once* to init ___it */		\
			       *___p __attribute__((unused)) = (				\
					bpf_iter_##type##_new(&___it, ##args),			\
	/* this is a workaround for Clang bug: it currently doesn't emit BTF */			\
	/* for bpf_iter_##type##_destroy() when used from cleanup() attribute */		\
					(void)bpf_iter_##type##_destroy, (void *)0);		\
	/* iteration and termination check */							\
	(((cur) = bpf_iter_##type##_next(&___it)));						\
)
#endif /* bpf_for_each */

#ifndef bpf_for
/* bpf_for(i, start, end) implements a for()-like looping construct that sets
 * provided integer variable *i* to values starting from *start* through,
 * but not including, *end*. It also proves to BPF verifier that *i* belongs
 * to range [start, end), so this can be used for accessing arrays without
 * extra checks.
 *
 * Note: *start* and *end* are assumed to be expressions with no side effects
 * and whose values do not change throughout bpf_for() loop execution. They do
 * not have to be statically known or constant, though.
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring for()
 * loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_for(i, start, end) for (								\
	/* initialize and define destructor */							\
	struct bpf_iter_num ___it __attribute__((aligned(8), /* enforce, just in case */	\
						 cleanup(bpf_iter_num_destroy))),		\
	/* ___p pointer is necessary to call bpf_iter_num_new() *once* to init ___it */		\
			    *___p __attribute__((unused)) = (					\
				bpf_iter_num_new(&___it, (start), (end)),			\
	/* this is a workaround for Clang bug: it currently doesn't emit BTF */			\
	/* for bpf_iter_num_destroy() when used from cleanup() attribute */			\
				(void)bpf_iter_num_destroy, (void *)0);				\
	({											\
		/* iteration step */								\
		int *___t = bpf_iter_num_next(&___it);						\
		/* termination and bounds check */						\
		(___t && ((i) = *___t, (i) >= (start) && (i) < (end)));				\
	});											\
)
#endif /* bpf_for */

#ifndef bpf_repeat
/* bpf_repeat(N) performs N iterations without exposing iteration number
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring for()
 * loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_repeat(N) for (									\
	/* initialize and define destructor */							\
	struct bpf_iter_num ___it __attribute__((aligned(8), /* enforce, just in case */	\
						 cleanup(bpf_iter_num_destroy))),		\
	/* ___p pointer is necessary to call bpf_iter_num_new() *once* to init ___it */		\
			    *___p __attribute__((unused)) = (					\
				bpf_iter_num_new(&___it, 0, (N)),				\
	/* this is a workaround for Clang bug: it currently doesn't emit BTF */			\
	/* for bpf_iter_num_destroy() when used from cleanup() attribute */			\
				(void)bpf_iter_num_destroy, (void *)0);				\
	bpf_iter_num_next(&___it);								\
	/* nothing here  */									\
)
#endif /* bpf_repeat */
#else
/*
 * Fallback to standard iteration for everybody else.
 */

#ifndef bpf_for
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#endif /* bpf_for */

#ifndef bpf_repeat
#define bpf_repeat(N) for (int i = 0; i < (N); i++)
#endif /* bpf_repeat */

#endif /* __V612_BPF_PROG */
#endif //__BPF_HELPERS_
