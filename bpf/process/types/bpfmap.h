// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPFMAP_H__
#define __BPFMAP_H__

#include "bpfattr.h"

struct bpf_map_info_type {
	__u32 map_type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	char map_name[BPF_OBJ_NAME_LEN];
};

#endif
