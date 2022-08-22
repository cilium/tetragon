// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __BPF_CGROUP_
#define __BPF_CGROUP_

#include "hubble_msg.h"
#include "bpf_helpers.h"
#include "environ_conf.h"
#include "process.h"

#define NULL ((void *)0)

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb /* Cgroupv1 pseudo FS */
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270 /* Cgroupv2 pseudo FS */
#endif

/* kernfs node name length */
#define KN_NAME_LENGTH 128

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

static inline __attribute__((always_inline)) struct kernfs_node *
__get_cgroup_kn(const struct cgroup *cgrp)
{
	struct kernfs_node *kn = NULL;

	if (cgrp)
		probe_read(&kn, sizeof(cgrp->kn), _(&cgrp->kn));

	return kn;
}

static inline __attribute__((always_inline)) const char *
__get_cgroup_kn_name(const struct kernfs_node *kn)
{
	const char *name = NULL;

	if (kn)
		probe_read(&name, sizeof(name), _(&kn->name));

	return name;
}

static inline __attribute__((always_inline)) __u64
__get_cgroup_knfs_id(const struct kernfs_node *kn)
{
	__u64 id = 0;

	if (kn)
		probe_read(&id, sizeof(id), _(&kn->id));

	return id;
}

static inline __attribute__((always_inline)) __u32
get_cgroup_hierarchy_id(const struct cgroup *cgrp)
{
	__u32 id = 0;
	struct cgroup_root *root = NULL;

	probe_read(&root, sizeof(root), _(&cgrp->root));
	if (root)
		probe_read(&id, sizeof(id), _(&root->hierarchy_id));

	return id;
}

static inline __attribute__((always_inline)) struct cgroup *
get_task_cgroup(struct task_struct *task)
{
	struct cgroup_subsys_state *subsys;
	struct css_set *cgroups;
	struct cgroup *cgrp = NULL;

	probe_read(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if (unlikely(!cgroups))
		return cgrp;

	probe_read(&subsys, sizeof(subsys), _(&cgroups->subsys[0]));
	if (unlikely(!subsys))
		return cgrp;

	probe_read(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
	return cgrp;
}

static inline __attribute__((always_inline)) __u32
get_cgroup_level(const struct cgroup *cgrp)
{
	__u32 level = 0;

	probe_read(&level, sizeof(level), _(&cgrp->level));
	return level;
}

static inline __attribute__((always_inline)) __u64
get_cgroup_id(const struct cgroup *cgrp)
{
	struct kernfs_node *kn;

	kn = __get_cgroup_kn(cgrp);
	return __get_cgroup_knfs_id(kn);
}

static inline __attribute__((always_inline)) __u64
get_task_cgroup_id(struct task_struct *task)
{
	__u64 cgrpid = 0;
	struct cgroup *cgrp;

	cgrp = get_task_cgroup(task);
	if (cgrp)
		cgrpid = get_cgroup_id(cgrp);

	return cgrpid;
}

static inline __attribute__((always_inline)) __u64
get_ancestor_cgroup_id(const struct cgroup *cgrp, __u64 cgrpfs_ver,
		       __u32 ancestor_level)
{
	__u32 level;
	__u64 id = 0;

	if (unlikely(ancestor_level == 0))
		return id;

#ifdef BPF_FUNC_get_current_ancestor_cgroup_id
	if (cgrpfs_ver == CGROUP2_SUPER_MAGIC)
		id = get_current_ancestor_cgroup_id(ancestor_level);
#endif

	if (id > 0)
		return id;

	level = get_cgroup_level(cgrp);
	if (level > ancestor_level)
		probe_read(&id, sizeof(id),
			   _(&cgrp->ancestor_ids[ancestor_level]));

	return id;
}

static inline __attribute__((always_inline)) struct cgroup_tracking_value *
__get_cgrp_tracking_val_heap(cgroup_state state, __u32 hierarchy_id,
			     __u32 level)
{
	int zero = 0;
	struct cgroup_tracking_value *heap;

	heap = map_lookup_elem(&tg_cgrps_tracking_heap, &zero);
	if (!heap)
		return heap;

	memset(heap, 0, sizeof(struct cgroup_tracking_value));
	heap->state = state;
	heap->hierarchy_id = hierarchy_id;
	heap->level = level;

	return heap;
}

static inline __attribute__((always_inline)) struct cgroup_tracking_value *
__init_cgrp_tracking_val_heap(struct cgroup *cgrp, cgroup_state state)
{
	const char *name;
	struct kernfs_node *kn;
	__u32 level, hierarchy_id;
	struct cgroup_tracking_value *heap;

	hierarchy_id = get_cgroup_hierarchy_id(cgrp);
	level = get_cgroup_level(cgrp);
	heap = __get_cgrp_tracking_val_heap(state, hierarchy_id, level);
	if (!heap)
		return heap;

	kn = __get_cgroup_kn(cgrp);
	name = __get_cgroup_kn_name(kn);
	if (name)
		probe_read_str(&heap->name, KN_NAME_LENGTH - 1, name);

	return heap;
}

/* Sets task cgrpid_tracker of a task. It reads tetragon_conf if not
 * available then exit.
 * If tetragon_conf is available then checks if the task
 * execve_map_value->cgrpid_tracker is set, if so do nothing.
 * If not set then fetch task cgroup and cgroup level, compare it against
 * tetragon_conf->tg_cgrp_level which is the tracking cgroup level and set
 * the task execve_map_value->cgrpid_tracker accordingly.
 */
static inline __attribute__((always_inline)) int
__set_task_cgrpid_tracker(struct tetragon_conf *conf, struct task_struct *task,
			  struct execve_map_value *execve_val)
{
	struct cgroup *cgrp;
	struct cgroup_tracking_value *cgrp_data;
	u32 level = 0, hierarchy_id = 0, tracking_level = 0, flags = 0;

	if (unlikely(!conf) || unlikely(!execve_val))
		return 0;

	probe_read(&flags, sizeof(flags), _(&task->flags));
	if (flags & PF_KTHREAD)
		return 0;

	/* Set the tracking cgroup id only if it was not set,
	 * this avoids cgroup thread granularity mess!.
	 */
	if (execve_val->cgrpid_tracker != 0)
		return 0;

	cgrp = get_task_cgroup(task);
	level = get_cgroup_level(cgrp);

	if (level <= conf->tg_cgrp_level) {
		/* Set this as the tracking cgroup of the task since it is before the
		 * tracked level. This means this is probably a Pod or Container level
		 * Anything below will be attached to this tracker
		 */
		execve_val->cgrpid_tracker = get_cgroup_id(cgrp);
		tracking_level = level;
	} else {
		/* Set the ancestor that is at the tracked level as the tracking cgroup */
		execve_val->cgrpid_tracker = get_ancestor_cgroup_id(
			cgrp, conf->cgrp_fs_magic, conf->tg_cgrp_level);
		tracking_level = conf->tg_cgrp_level;
	}

	cgrp_data = map_lookup_elem(&tg_cgrps_tracking_map,
				    &execve_val->cgrpid_tracker);
	if (!cgrp_data) {
		/* This was never tracked let's push it here */
		hierarchy_id = get_cgroup_hierarchy_id(cgrp);
		cgrp_data = __get_cgrp_tracking_val_heap(
			CGROUP_RUNNING, hierarchy_id, tracking_level);
		if (cgrp_data)
			map_update_elem(&tg_cgrps_tracking_map,
					&execve_val->cgrpid_tracker, cgrp_data,
					BPF_ANY);
	} else if (cgrp_data->state != CGROUP_RUNNING) {
		/* Convert to cgroup running now as we are able to track it */
		cgrp_data->state = CGROUP_RUNNING;
	}

	return 0;
}

#endif // __BPF_CGROUP_
