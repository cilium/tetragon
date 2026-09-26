// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_MAPS_H__
#define __GENERIC_MAPS_H__

#include "lib/data_msg.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

/* LSM-only heap, keyed by task (pid_tgid) instead of a fixed per-CPU
 * slot. The LSM tail-call chain (setup -> filter -> args -> actions ->
 * output) can otherwise let two separately-attached programs on the
 * same LSM hook read/clobber the same shared per-CPU entry if their
 * executions interleave on the same CPU. Entries are created lazily on
 * first use and explicitly removed once the chain finishes (see
 * lsm_heap_delete() in bpf_generic_lsm_output.c / bpf_generic_lsm_core.c),
 * so sizing does not depend on LRU eviction guesswork.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct msg_generic_kprobe);
} lsm_call_heap SEC(".maps");

/* Looks up this task's entry in lsm_call_heap, creating a zeroed one on
 * first use. Safe against a concurrent insert race (e.g. the same task
 * migrating CPUs mid-chain): BPF_NOEXIST means a losing insert simply
 * re-reads the entry the winner just created instead of overwriting it.
 */
static __always_inline struct msg_generic_kprobe *
lsm_heap_get_or_create(void)
{
	__u64 pid_tgid = get_current_pid_tgid();
	struct msg_generic_kprobe *e;
	struct msg_generic_kprobe zero_val = {};

	e = map_lookup_elem(&lsm_call_heap, &pid_tgid);
	if (e)
		return e;

	if (map_update_elem(&lsm_call_heap, &pid_tgid, &zero_val, BPF_NOEXIST))
		return map_lookup_elem(&lsm_call_heap, &pid_tgid);

	return map_lookup_elem(&lsm_call_heap, &pid_tgid);
}

/* Explicitly removes this task's entry once the LSM tail-call chain has
 * finished (event emitted, or the chain was rejected/short-circuited
 * early). Called instead of relying on LRU eviction so an entry never
 * outlives the exact chain invocation that created it.
 */
static __always_inline void
lsm_heap_delete(void)
{
	__u64 pid_tgid = get_current_pid_tgid();

	map_delete_elem(&lsm_call_heap, &pid_tgid);
}

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
