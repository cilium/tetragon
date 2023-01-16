// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef POLICY_FILTER_MAPS_H__
#define POLICY_FILTER_MAPS_H__

#include "bpf_tracing.h"

#define POLICY_FILTER_MAX_POLICIES 128

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
	__uint(key_size, sizeof(u32)); /* policy id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u64); /* cgroup id */
			__type(value, __u8); /* empty  */
		});
} policy_filter_maps SEC(".maps");

// policy_filter_check checks whether the policy applies on the current process.
// Returns true if it does, false otherwise.
static inline __attribute__((always_inline)) bool
policy_filter_check(u32 policy_id)
{
	__u32 pid;
	void *policy_map;
	struct execve_map_value *curr;

	if (!policy_id)
		return true;

	pid = (get_current_pid_tgid() >> 32);
	curr = execve_map_get_noinit(pid);
	if (!curr || curr->cgrpid_tracker == 0)
		return false;

	policy_map = map_lookup_elem(&policy_filter_maps, &policy_id);
	if (!policy_map)
		return false;

	return map_lookup_elem(policy_map, &curr->cgrpid_tracker);
}

#endif /* POLICY_FILTER_MAPS_H__ */
