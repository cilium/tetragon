// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __ENVIRON_CONF_
#define __ENVIRON_CONF_

/* Tetragon runtime configuration */
struct tetragon_conf {
	__u32 tg_cgrp_hierarchy; /* Tetragon tracked hierarchy ID */
	__u32 tg_cgrp_subsys_idx; /* Tetragon tracked cgroup subsystem state index at compile time */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct tetragon_conf);
} tg_conf_map SEC(".maps");

#endif // __ENVIRON_CONF_
