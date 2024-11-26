// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef CGTRACKER_H__
#define CGTRACKER_H__

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64); /* cgroup id */
	__type(value, __u64); /* tracker cgroup id */
} tg_cgtracker_map SEC(".maps");

FUNC_INLINE __u64 cgrp_get_tracker_id(__u64 cgid)
{
	__u64 *ret;

	ret = map_lookup_elem(&tg_cgtracker_map, &cgid);
	return ret ? *ret : 0;
}

#endif /* CGTRACKER_H__ */
