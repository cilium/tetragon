// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __HEAP_H__
#define __HEAP_H__

#define HEAP_RO_SIZE 26232

struct heap_ro_value {
	/*
	 * STRING_MAPS_HEAP_SIZE
	 * sizeof(struct ratelimit_key) + 128
	 * sizeof(struct msg_generic_kprobe)
	 * sizeof(struct buffer_heap_map_value)
	 * sizeof(struct string_prefix_lpm_trie)
	 * sizeof(struct string_postfix_lpm_trie)
	 */
	char buf[HEAP_RO_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_ro_value);
} heap_ro_zero SEC(".maps");

struct heap_value {
	union {
		char fdinstall[4104]; /* 4096B paths + 4B length + 4B flags */
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_value);
} heap SEC(".maps");

/* Uprobe/uretprobe/usdt probes run in a context that does not disable
 * preemption, unlike kprobes/tracepoints, so their per-process heap maps
 * need to be hashes (keyed by pid_tgid) instead of per-cpu arrays.
 *
 * Same for fentry/fexit and lsm, the bpf trampoline only disables migration.
 */
#if defined(GENERIC_UPROBE) || defined(GENERIC_URETPROBE) || defined(GENERIC_USDT) || \
	defined(GENERIC_FENTRY) || defined(GENERIC_FEXIT) || defined(GENERIC_LSM)
#define USE_HASH_HEAP
#endif

#ifdef USE_HASH_HEAP

typedef __u64 heap_key_t;

/* The context helpers use BPF APIs available in the v5.11+ object variants. */
#if (defined(GENERIC_FENTRY) || defined(GENERIC_FEXIT) || defined(GENERIC_LSM)) && \
	defined(__V511_BPF_PROG)
#include "bpf_context.h"

/* The context key separates nested invocations on different interrupt
 * context levels. Nesting of the same fentry/fexit program on the same
 * level is prevented by the kernel recursion check, but the heap maps are
 * shared by all programs, so a different program nesting on the same level
 * (attached to a kernel function called from a helper of the outer program)
 * gets the same key and overwrites the outer entry, the outer event is lost
 * (counted as EEXIST in errmetrics). Lsm programs have no recursion check.
 */
static inline __attribute__((always_inline)) heap_key_t get_context_key(void)
{
	__u64 tid = (__u32)get_current_pid_tgid();
	__u64 cpu = get_smp_processor_id();
	__u64 ctx = interrupt_context_level();

	return tid << 32 | (cpu & 0xffffff) << 8 | ctx;
}
#endif

/* All hash heaps must use the same key, heap_dtor releases them together. */
static inline __attribute__((always_inline)) heap_key_t heap_key(void)
{
#if (defined(GENERIC_FENTRY) || defined(GENERIC_FEXIT) || defined(GENERIC_LSM)) && \
	defined(__V511_BPF_PROG)
	return get_context_key();
#else
	return get_current_pid_tgid();
#endif
}

#else

typedef __u32 heap_key_t;

static inline __attribute__((always_inline)) heap_key_t heap_key(void)
{
	return 0;
}

#endif /* USE_HASH_HEAP */

#endif // __HEAP_H__
