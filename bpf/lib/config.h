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
	__u8 PARENTS_MAP_ENABLED;
	__u8 BPF_DEBUG_ENABLED;
	__u8 pad[3];
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
 * PARENTS_MAP_ENABLED/ENV_VARS_ENABLED/BPF_DEBUG_ENABLED don't have that problem -
 * their call sites are plain guards with no alternate branch, so they work
 * fine as ordinary runtime values on any kernel.
 */
#ifdef __LARGE_BPF_PROG
volatile const __u8 PARENTS_MAP_ENABLED;
volatile const __u8 ENV_VARS_ENABLED;
volatile const __u8 BPF_DEBUG_ENABLED;
#define ITER_NUM     0
#define CONFIG(name) name
#else
#define CONFIG(name) 0
#endif /* __LARGE_BPF_PROG */

#endif /* __V511_BPF_PROG */

/*
 * FEATURE_MASK is rewritten by the agent on __LARGE_BPF_PROG based on the
 * defined selectors. This allows us to do dead code elimination in unused
 * eBPF code related to specific selectors.
 * In non-__LARGE_BPF_PROG programs, we always have all selectors enabled.
 */
#ifdef __LARGE_BPF_PROG
volatile const __u32 FEATURE_MASK = 0xFFFFFFFF;
#else
#define FEATURE_MASK 0xFFFFFFFF
#endif /* __LARGE_BPF_PROG */

#define HAS_MATCH_PIDS		     (FEATURE_MASK & (1 << 1))
#define HAS_MATCH_NAMESPACES	     (FEATURE_MASK & (1 << 2))
#define HAS_MATCH_CAPABILITIES	     (FEATURE_MASK & (1 << 3))
#define HAS_MATCH_NAMESPACE_CHANGES  (FEATURE_MASK & (1 << 4))
#define HAS_MATCH_CAPABILITY_CHANGES (FEATURE_MASK & (1 << 5))
#define HAS_MATCH_BINARIES	     (FEATURE_MASK & (1 << 6))
#define HAS_MATCH_PARENT_BINARIES    (FEATURE_MASK & (1 << 7))
#define HAS_MATCH_CMD_ARGS	     (FEATURE_MASK & (1 << 8))
#define HAS_MATCH_WORKLOADS	     (FEATURE_MASK & (1 << 9))
#define HAS_MATCH_USER_CALLERS	     (FEATURE_MASK & (1 << 10))
#define HAS_MATCH_CEL		     (FEATURE_MASK & (1 << 11))
#define HAS_MATCH_ARG_FILTERS	     (FEATURE_MASK & (1 << 12))
