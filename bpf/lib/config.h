// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#define __field(name) name

/*
 * Read a field from a frozen, read-only rodata map, reconstructing the map
 * pointer on each access to prevent the compiler from reusing it across
 * multiple accesses in short succession. This makes branches based on
 * config variables more likely to be predictable using backtracking, since
 * load/deref/branch will be close to each other and the pointer won't be
 * reused across basic blocks.
 *
 * Specifying the global map pointer as an asm input gives enough
 * information to the compiler to allow it to reuse the pointer across
 * blocks, so opt for a direct symbol reference instead. We need the
 * pointer reconstructed in bytecode on every access.
 */
#define __CONFIG_FIELD(map, type, field)                      \
	({                                                    \
		void *out;                                    \
		asm volatile("%0 = " #map " ll"               \
			     : "=r"(out));                    \
		((volatile const type *)out)->__field(field); \
	})

#ifdef __V511_BPF_PROG

struct rodata_config {
	__u8 ITER_NUM;
	__u8 USE_PERF_RING_BUF;
	__u8 ENV_VARS_ENABLED;
	__u8 pad[5];
};

volatile const struct rodata_config rodata_config
	__attribute__((section(".rodata.config"), used));

#define CONFIG(name) __CONFIG_FIELD(rodata_config, struct rodata_config, name)

#else

/*
 * CONFIG() above relies on the verifier reading a frozen map's known
 * value to prune the dead branch - support for that only landed in
 * kernel v5.5 ("bpf: Track contents of read-only maps as scalars",
 * a23740ec43ba), so this pre-5.11 tier can't assume it's present.
 *
 * ITER_NUM must stay a compile-time 0 because it guards a full second
 * implementation (iterator loop vs. unrolled loop) at each call site;
 * without compile-time elimination both get verified, which failed to
 * load on a real v5.4 kernel in CI.
 *
 * ENV_VARS_ENABLED doesn't have that problem - its call site is a plain
 * guard with no alternate branch, so it works fine as an ordinary
 * runtime value on any kernel.
 */
#ifdef __LARGE_BPF_PROG
volatile const __u8 ENV_VARS_ENABLED;
#define ITER_NUM     0
#define CONFIG(name) name
#else
#define CONFIG(name) 0
#endif /* __LARGE_BPF_PROG */

#endif /* __V511_BPF_PROG */
