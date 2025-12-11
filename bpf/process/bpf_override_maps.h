// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _BPF_OVERRIDE_MAPS__
#define _BPF_OVERRIDE_MAPS__

#include "lib/data_msg.h"

struct override_target {
	__u64 id;
	__u64 pid_tgid;
};

struct override_config {
	__u32 override_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct override_config);
} override_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, struct override_target);
	__type(value, __s32);
} override_tasks SEC(".maps");

#endif