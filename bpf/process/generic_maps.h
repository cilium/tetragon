// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_MAPS_H__
#define __GENERIC_MAPS_H__

#include "lib/data_msg.h"

/*
 * Sleepable uprobe programs use BPF_MAP_TYPE_TASK_STORAGE so that each task
 * gets its own scratch buffer.  A per-CPU array would be corrupted if the
 * sleepable program is preempted and another task hits the same probe on the
 * same CPU before the first task resumes.
 */
#ifdef __SLEEPABLE
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

FUNC_INLINE struct msg_generic_kprobe *process_call_heap_lookup(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();

	return task_storage_get((struct bpf_map *) &process_call_heap, task, NULL,
				BPF_LOCAL_STORAGE_GET_F_CREATE);
}
#else
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

FUNC_INLINE struct msg_generic_kprobe *process_call_heap_lookup(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&process_call_heap, &zero);
}
#endif

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
