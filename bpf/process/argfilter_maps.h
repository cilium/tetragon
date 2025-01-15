// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef ARGFILTER_MAPS_H__
#define ARGFILTER_MAPS_H__

#define ARGFILTER_MAPS_OUTER_MAX_ENTRIES 8

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, ARGFILTER_MAPS_OUTER_MAX_ENTRIES);
	__type(key, __u32);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u64);
			__type(value, __u8);
		});
} argfilter_maps SEC(".maps");

#endif // ARGFILTER_MAPS_H__
