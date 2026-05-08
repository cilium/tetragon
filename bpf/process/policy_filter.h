// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef POLICY_FILTER_MAPS_H__
#define POLICY_FILTER_MAPS_H__

#include "bpf_tracing.h"
#include "cgroup/cgtracker.h"

#define POLICY_FILTER_MAX_POLICIES   128
#define POLICY_FILTER_MAX_CGROUP_IDS 1024

#define ALL_PODS_POLICY_ID 0x01
#define HOST_SELECTOR_MODE 0xFFFFFFFFFFFFFFFFull

// In order to implement the hostSelector we add one more entry in the outer map
// that is not related to any specific policy. This entry has policy_id equals
// to ALL_PODS_POLICY_ID. In that case the inner map contains the cgroup_ids for
// *all* containers inside *all* pods. This allows us to generate a mechanism to
// match (i) on all pods or (ii) in none of the pods (which is the same as the
// host workload).
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, POLICY_FILTER_MAX_POLICIES);
	__type(key, u32); /* policy id */
	__array(
		// If a specific policy needs to match on host workloads as well we also
		// add an entry with key HOST_SELECTOR_MODE (UINT64_MAX).
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

/**
 * tg_get_current_cgrp_tracker_id() Returns tracker cgroup id of the current task or 0 on failure
 */
FUNC_INLINE __u64 tg_get_current_cgrp_tracker_id(void)
{
	__u64 cgroupid, trackerid;

	cgroupid = tg_get_current_cgroup_id();
	if (!cgroupid)
		return 0;

	trackerid = cgrp_get_tracker_id(cgroupid);
	if (trackerid)
		cgroupid = trackerid;

	return cgroupid;
}

// policy_filter_check__ checks whether the policy applies on a given cgroup id.
// Returns true if it does, false otherwise.
FUNC_INLINE bool policy_filter_check__(__u32 policy_id, __u64 cgroupid)
{
	void *policy_map;

	if (!policy_id)
		return true;

	if (!cgroupid)
		return false;

	policy_map = map_lookup_elem(&policy_filter_maps, &policy_id);
	if (!policy_map)
		return false;

	if (map_lookup_elem(policy_map, &cgroupid))
		return true; // We have a match from the podSelector and/or the containerSelector.

	// We didn't match on the podSelector and/or the containerSelector.
	// Now we need to check if we have a hostSelector match.

	{
		__u64 trackerid = HOST_SELECTOR_MODE;

		if (!map_lookup_elem(policy_map, &trackerid))
			return false; // Cannot find the match mode of the hostSelector so we do not care to match any host workloads.
	}

	{
		__u32 all_pods_id = ALL_PODS_POLICY_ID;

		policy_map = map_lookup_elem(&policy_filter_maps, &all_pods_id);
		if (!policy_map)
			return false; // Cannot find the cgroupids of all containers inside all pods. This should not happen.
	}

	// If !map_lookup_elem(policy_map, &cgroupid) then our cgroupid belongs to a host workload.
	return !map_lookup_elem(policy_map, &cgroupid);
}

// policy_filter_check checks whether the policy applies on the current process.
// Returns true if it does, false otherwise.
FUNC_INLINE bool policy_filter_check(__u32 policy_id)
{
	__u64 cgroupid;

	cgroupid = tg_get_current_cgrp_tracker_id();
	return policy_filter_check__(policy_id, cgroupid);
}

#endif /* POLICY_FILTER_MAPS_H__ */
