// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_MAPS_H__
#define __GENERIC_MAPS_H__

#include "lib/data_msg.h"
#include "lib/bpf_d_path.h"
#include "errmetrics.h"
#include "heap.h"

/*
 * The uprobe/usdt probes path in kernel do not disable preemption,
 * we need to use hash instead of per-cpu heap.
 */
#ifdef USE_HASH_HEAP

typedef __u64 heap_key_t;

/* The context helpers use BPF APIs available in the v5.11+ object variants. */
#if (defined(GENERIC_FENTRY) || defined(GENERIC_FEXIT) || defined(GENERIC_LSM)) && \
	defined(__V511_BPF_PROG)
#include "bpf_context.h"

static inline __attribute__((always_inline)) heap_key_t get_context_key(void)
{
	__u64 tid = (__u32)get_current_pid_tgid();
	__u64 cpu = get_smp_processor_id();
	__u64 ctx = interrupt_context_level();

	return tid << 32 | (cpu & 0xffffff) << 8 | ctx;
}
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1); // will be resized by agent
	__type(key, heap_key_t);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

FUNC_INLINE heap_key_t heap_key(void)
{
#if (defined(GENERIC_FENTRY) || defined(GENERIC_FEXIT) || defined(GENERIC_LSM)) && \
	defined(__V511_BPF_PROG)
	return get_context_key();
#else
	return get_current_pid_tgid();
#endif
}

FUNC_INLINE bool heap_update(heap_key_t key)
{
	struct heap_ro_value *ro;
	int zidx = 0;

	if (map_lookup_elem(&process_call_heap, &key))
		errmetrics(EEXIST);

	ro = map_lookup_elem(&heap_ro_zero, &zidx);
	if (!ro)
		return false;
	if (map_update_elem(&process_call_heap, &key, ro, BPF_ANY)) {
		errmetrics(E2BIG);
		return false;
	}
	return true;
}

#else

typedef __u32 heap_key_t;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

FUNC_INLINE heap_key_t heap_key(void)
{
	return 0;
}

FUNC_INLINE bool heap_update(heap_key_t key)
{
	return true;
}

#endif /* USE_HASH_HEAP */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, __s32);
} override_tasks SEC(".maps");

#ifdef __LARGE_BPF_PROG
#if defined(GENERIC_TRACEPOINT) || defined(GENERIC_UPROBE)
#define data_heap_ptr 0
#else
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");
#define data_heap_ptr (struct bpf_map_def *)&data_heap
#endif
#else
#define data_heap_ptr 0
#endif

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_config);
} config_map SEC(".maps");

#ifdef GENERIC_USDT
struct write_offload_data {
	unsigned long addr;
	unsigned int value;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, struct write_offload_data);
} write_offload SEC(".maps");
#endif

#ifdef USE_HASH_HEAP

FUNC_INLINE long heap_dtor(long ret)
{
	__u64 key = get_current_pid_tgid();

	map_delete_elem(&process_call_heap, &key);
	map_delete_elem(&buffer_heap_map, &key);
	map_delete_elem(&string_maps_heap, &key);
	map_delete_elem(&string_prefix_maps_heap, &key);
	map_delete_elem(&string_postfix_maps_heap, &key);
	map_delete_elem(&ratelimit_heap, &key);
	return ret;
}

#else

FUNC_INLINE long heap_dtor(long ret)
{
	return ret;
}

#endif /* USE_HASH_HEAP */

#endif // __GENERIC_MAPS_H__
