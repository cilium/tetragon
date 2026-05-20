// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#ifdef __LARGE_BPF_PROG

struct tg_rodata_config {
	__u8 iter_num;
	__u8 parents_map_enabled;
	__u8 env_vars_enabled;
	__u8 pad[5];
};

volatile const struct tg_rodata_config tg_rodata_config
	__attribute__((section(".rodata.tg_cfg"), used));

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
#define TG_RODATA_CONFIG_PTR()                                      \
	({                                                        \
		void *out;                                            \
		asm volatile("%0 = tg_rodata_config ll"               \
			     : "=r"(out));                            \
		(volatile const struct tg_rodata_config *)out;        \
	})

#define TG_RODATA_CONFIG(field) (TG_RODATA_CONFIG_PTR()->field)

#define PARENTS_MAP_ENABLED TG_RODATA_CONFIG(parents_map_enabled)
#define ENV_VARS_ENABLED    TG_RODATA_CONFIG(env_vars_enabled)

#ifdef __V511_BPF_PROG

#define CONFIG(name) TG_RODATA_CONFIG(iter_num)

#else /* __V511_BPF_PROG */

#define CONFIG(name) 0

#endif /* __V511_BPF_PROG */

#else /* __LARGE_BPF_PROG */

#define CONFIG(name) 0

#endif /* __LARGE_BPF_PROG */
