// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef ADDR_LPM_MAPS_H__
#define ADDR_LPM_MAPS_H__

#define ADDR_LPM_MAPS_OUTER_MAX_ENTRIES 8

struct addr4_lpm_trie {
	__u32 prefix;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, ADDR_LPM_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[8]); // Need to specify as byte array as wouldn't take struct as key type
			__type(value, __u8);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} addr4lpm_maps SEC(".maps");

#endif // ADDR_LPM_MAPS_H__
