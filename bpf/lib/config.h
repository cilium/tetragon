// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#ifdef __V511_BPF_PROG

struct rodata_config {
	__u8 ITER_NUM;
       __u8 pad[7];
};

volatile const struct rodata_config rodata_config
	__attribute__((section(".rodata.config"), used));

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
#define RODATA_CONFIG_PTR()                                           \
        ({                                                            \
		void *out;                                            \
		asm volatile("%0 = rodata_config ll"                  \
			     : "=r"(out));                            \
		(volatile const struct rodata_config *)out;           \
	})

#define CONFIG(name) (RODATA_CONFIG_PTR()->name)

#else

/*
 * We allow to set ENV_VARS_ENABLED/PARENTS_MAP_ENABLED in
 * large programs, ITER_NUM is disabled.
 * v4.19 has everything disabled.
 */
#ifdef __LARGE_BPF_PROG
volatile const __u8 ENV_VARS_ENABLED;
volatile const __u8 PARENTS_MAP_ENABLED;
#define ITER_NUM 0
#define CONFIG(name) name
#else
#define CONFIG(name) 0
#endif /* __LARGE_BPF_PROG */

#endif /* __V511_BPF_PROG */
