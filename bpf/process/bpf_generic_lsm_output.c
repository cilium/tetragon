// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_LSM

#include "compiler.h"
#include "bpf_event.h"
#ifdef __LARGE_MAP_KEYS
#include "bpf_lsm_ima.h"
#endif
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, __s32);
} override_tasks SEC(".maps");

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

FUNC_INLINE int try_override(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error;

	error = map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	map_delete_elem(&override_tasks, &id);
	return (long)*error;
}

__attribute__((section("lsm/generic_lsm_output"), used)) int
generic_lsm_output(void *ctx)
{
	struct msg_generic_kprobe *e;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;
#ifdef __LARGE_MAP_KEYS
	if (e && e->common.flags & MSG_COMMON_FLAG_IMA_HASH) {
		__u64 pid_tgid = get_current_pid_tgid();
		struct ima_hash *hash = map_lookup_elem(&ima_hash_map, &pid_tgid);

		if (hash && hash->state == 2) {
			// Copy hash after all arguments
			if (e->common.size + sizeof(struct ima_hash) <= 16383) {
				probe_read(&e->args[e->common.size & 16383], sizeof(struct ima_hash), (char *)hash);
				e->common.size += sizeof(struct ima_hash);
			}
			map_delete_elem(&ima_hash_map, &pid_tgid);
		}
	}
#endif
	if (e->lsm.post)
		generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_LSM);
	return try_override(ctx);
}
