// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef FILE_IDENTITY_MAPS_H__
#define FILE_IDENTITY_MAPS_H__

#define FILE_IDENTITY_MAPS_OUTER_MAX_ENTRIES 8

struct file_identity {
	__u64 inode;
	__u32 device;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, FILE_IDENTITY_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[12]);
			__type(value, __u8);
		});
} fileid_maps SEC(".maps");

#endif // FILE_IDENTITY_MAPS_H__
