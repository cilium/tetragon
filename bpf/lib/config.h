// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#ifdef __V511_BPF_PROG

#define DECLARE_CONFIG(type, name) \
	volatile const type CONFIG_##name;

/*
 * Reconstruct the rodata pointer on each access to prevent the compiler
 * from reusing the pointer across multiple accesses in short
 * succession. This makes branches based on config variables more likely
 * to be predictable using backtracking, since load/deref/branch will be
 * close to each other and the pointer won't be reused across basic
 * blocks.
 *
 * Specifying the global var ptr as an asm input gives enough
 * information to the compiler to allow it to reuse the pointer across
 * blocks, so opt for a direct symbol reference instead. We need the
 * pointer reconstructed in bytecode on every access.
 */
#define CONFIG(name)                                                  \
	(*({                                                          \
		void *out;                                            \
		asm volatile("%0 = " __stringify(CONFIG_##name) " ll" \
			     : "=r"(out));                            \
		(typeof(CONFIG_##name) *)out;                         \
	}))

DECLARE_CONFIG(bool, ITER_NUM);

#else

#define CONFIG(name) 0

#endif /* __V511_BPF_PROG */
