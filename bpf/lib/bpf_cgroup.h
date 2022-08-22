// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef _BPF_CGROUP__
#define _BPF_CGROUP__

#include "hubble_msg.h"
#include "bpf_helpers.h"
#include "process.h"

#define NULL ((void *)0)

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb /* Cgroupv1 pseudo FS */
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270 /* Cgroupv2 pseudo FS */
#endif

/* kernfs node name length */
#define KN_NAME_LENGTH 256

/* Max nested cgroups that are tracked. Arbitrary value, nested cgroups
 * that are at a level greater than 32 will be attached to the cgroup
 * at level 32.
 */
#define CGROUP_MAX_NESTED_LEVEL 32

typedef enum {
	CGROUP_UNTRACKED = 0, /* Cgroup was created but we did not track it */
	CGROUP_NEW = 1, /* Cgroup was just created */
	CGROUP_RUNNING = 2, /* new => running (fork,exec task inside) */
	CGROUP_RUNNING_PROC = 3, /* Generated from pids of procfs */
} cgroup_state;

struct cgroup_tracking_value {
	/* State of cgroup */
	cgroup_state state;

	/* Unique id for the hierarchy this is mostly for cgroupv1 */
	__u32 hierarchy_id;

	/* The depth this cgroup is at */
	__u32 level;

	__u32 pad;

	/* Cgroup kernfs_node name */
	char name[KN_NAME_LENGTH];
} __attribute__((packed));

struct msg_cgroup_event {
	struct msg_common common;
	struct msg_execve_key parent;
	__u32 cgrp_op; /* Current cgroup operation */
	__u32 pid;
	__u32 nspid;
	__u32 flags;
	__u64 ktime;
	__u64 cgrpid_tracker; /* Cgroup ID that is used as a tracker for the current cgroup */
	__u64 cgrpid; /* Current cgroup ID */
	struct cgroup_tracking_value cgrp_data; /* Current cgroup data */
	char path[PATH_MAP_SIZE]; /* Current cgroup path */
} __attribute__((packed));

struct bpf_map_def __attribute__((section("maps"), used))
tg_cgrps_tracking_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct cgroup_tracking_value),
	.max_entries = 32768,
};

struct bpf_map_def __attribute__((section("maps"), used))
tg_cgrps_tracking_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(struct cgroup_tracking_value),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) tg_cgrps_msg_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_cgroup_event),
	.max_entries = 1,
};

#endif
