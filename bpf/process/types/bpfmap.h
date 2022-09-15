// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __BPFMAP_H__
#define __BPFMAP_H__

struct bpf_map_info_type {
	__u32 map_type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	char map_name[16U];
};

#endif
