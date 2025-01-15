// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef POLICY_FILTER_MAPS_H__
#define POLICY_FILTER_MAPS_H__

#include "bpf_tracing.h"
#include "cgroup/cgtracker.h"

#define POLICY_FILTER_MAX_POLICIES   128
#define POLICY_FILTER_MAX_NAMESPACES 1024
#define POLICY_FILTER_MAX_CGROUP_IDS 1024

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, POLICY_FILTER_MAX_NAMESPACES);
	__type(key, u64);
	__type(value, u64);
} tg_cgroup_namespace_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
	__type(key, u32); /* policy id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u64); /* cgroup id */
			__type(value, __u8); /* empty  */
		});
} policy_filter_maps SEC(".maps");

// This map keeps exactly the same information as policy_filter_maps
// but keeps the reverse mappings. i.e.
// policy_filter_maps maps policy_id to cgroup_ids
// policy_filter_cgroup_maps maps cgroup_id to policy_ids
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_CGROUP_IDS);
	__type(key, __u64); /* cgroup id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
			__type(key, __u32); /* policy id */
			__type(value, __u8); /* empty  */
		});
} policy_filter_cgroup_maps SEC(".maps");

// policy_filter_check checks whether the policy applies on the current process.
// Returns true if it does, false otherwise.

FUNC_INLINE bool policy_filter_check(u32 policy_id)
{
	void *policy_map;
	__u64 cgroupid, trackerid;

	if (!policy_id)
		return true;

	policy_map = map_lookup_elem(&policy_filter_maps, &policy_id);
	if (!policy_map)
		return false;

	cgroupid = tg_get_current_cgroup_id();
	if (!cgroupid)
		return false;

	trackerid = cgrp_get_tracker_id(cgroupid);
	if (trackerid)
		cgroupid = trackerid;

	return map_lookup_elem(policy_map, &cgroupid);
}

#endif /* POLICY_FILTER_MAPS_H__ */
