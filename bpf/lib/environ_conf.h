// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __ENVIRON_CONF_
#define __ENVIRON_CONF_

/* Tetragon runtime configuration */
struct tetragon_conf {
	__u32 loglevel; /* Tetragon log level */
	__u32 pid; /* Tetragon pid for debugging purpose */
	__u32 nspid; /* Tetragon pid in namespace for debugging purpose */
	__u32 tg_cgrp_hierarchy; /* Tetragon tracked hierarchy ID */
	__u32 tg_cgrp_subsys_idx; /* Tetragon tracked cgroup subsystem state index at compile time */
	__u32 tg_cgrp_level; /* Tetragon cgroup level */
	__u64 tg_cgrpid; /* Tetragon current cgroup ID to avoid filtering blocking itself */
	__u64 cgrp_fs_magic; /* Cgroupv1 or Cgroupv2 */
}; // All fields aligned so no 'packed' attribute.

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct tetragon_conf);
} tg_conf_map SEC(".maps");

#endif // __ENVIRON_CONF_
