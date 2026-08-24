// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_MAPS_H__
#define __GENERIC_MAPS_H__

#include "lib/data_msg.h"
#include "errmetrics.h"
#include "heap.h"

/*
 * The uprobe/usdt probes path in kernel do not disable preemption,
 * we need to use hash instead of per-cpu heap.
 */
#if defined(GENERIC_UPROBE) || defined(GENERIC_URETPROBE) || defined(GENERIC_USDT)

typedef __u64 heap_key_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1); // will be resized by agent
	__type(key, __u64);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

FUNC_INLINE heap_key_t heap_key(void)
{
	return get_current_pid_tgid();
}

FUNC_INLINE long heap_dtor(long ret)
{
	heap_key_t key = heap_key();

	map_delete_elem(&process_call_heap, &key);
	return ret;
}

/* Seeds a fresh process_call_heap entry for key from the read-only zero
 * template. Needed because map_update_elem() requires a value to copy from,
 * and one this size can't live on the BPF stack.
 */
FUNC_INLINE bool heap_update(heap_key_t key)
{
	struct heap_ro_value *ro;
	int zidx = 0;

	ro = map_lookup_elem(&heap_ro_zero, &zidx);
	if (!ro)
		return false;
	if (map_update_elem(&process_call_heap, &key, &ro->process_call_heap, BPF_ANY)) {
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

FUNC_INLINE long heap_dtor(long ret)
{
	return ret;
}

FUNC_INLINE bool heap_update(heap_key_t key)
{
	return true;
}

#endif /* GENERIC_UPROBE || GENERIC_URETPROBE || GENERIC_USDT */

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

#endif // __GENERIC_MAPS_H__
