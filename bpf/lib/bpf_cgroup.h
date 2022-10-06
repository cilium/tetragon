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

/* Our kernfs node name length, can be made 256? */
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

/* Represent old kernfs node with the kernfs_node_id
 * union to read the id in 5.4 kernels and older
 */
struct kernfs_node___old {
	union kernfs_node_id id;
};

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct cgroup_tracking_value);
} tg_cgrps_tracking_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct cgroup_tracking_value);
} tg_cgrps_tracking_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_cgroup_event);
} tg_cgrps_msg_heap SEC(".maps");

/**
 * get_cgroup_kn_name() Returns a pointer to the kernfs node name
 * @cgrp: target kernfs node
 *
 * Returns a pointer to the kernfs node name on success, NULL on failures.
 */
static inline __attribute__((always_inline)) const char *
__get_cgroup_kn_name(const struct kernfs_node *kn)
{
	const char *name = NULL;

	if (kn)
		probe_read(&name, sizeof(name), _(&kn->name));

	return name;
}

/**
 * get_cgroup_kn_id() Returns the kernfs node id
 * @cgrp: target kernfs node
 *
 * Returns the kernfs node id on success, zero on failures.
 */
static inline __attribute__((always_inline)) __u64
__get_cgroup_kn_id(const struct kernfs_node *kn)
{
	__u64 id = 0;

	if (!kn)
		return id;

	/* Kernels prior to 5.5 have the kernfs_node_id, but distros (RHEL)
	 * seem to have kernfs_node_id defined for UAPI reasons even though
	 * its not used here directly. To resolve this walk struct for id.id
	 */
	if (bpf_core_field_exists(((struct kernfs_node___old *)0)->id.id)) {
		struct kernfs_node___old *old_kn;

		old_kn = (void *)kn;
		if (BPF_CORE_READ_INTO(&id, old_kn, id.id) != 0)
			return 0;
	} else {
		probe_read(&id, sizeof(id), _(&kn->id));
	}

	return id;
}

/**
 * __get_cgroup_kn() Returns the kernfs_node of the cgroup
 * @cgrp: target cgroup
 *
 * Returns the kernfs_node of the cgroup on success, NULL on failures.
 */
static inline __attribute__((always_inline)) struct kernfs_node *
__get_cgroup_kn(const struct cgroup *cgrp)
{
	struct kernfs_node *kn = NULL;

	if (cgrp)
		probe_read(&kn, sizeof(cgrp->kn), _(&cgrp->kn));

	return kn;
}

/**
 * get_cgroup_hierarchy_id() Returns the cgroup hierarchy id
 * @cgrp: target cgroup
 *
 * Returns the cgroup hierarchy id. Make sure you pass a valid
 * cgroup, this can not fail.
 *
 * Returning zero means the cgroup is running on the default
 * hierarchy.
 */
static inline __attribute__((always_inline)) __u32
get_cgroup_hierarchy_id(const struct cgroup *cgrp)
{
	__u32 id;

	BPF_CORE_READ_INTO(&id, cgrp, root, hierarchy_id);

	return id;
}

/**
 * get_cgroup_name() Returns a pointer to the cgroup name
 * @cgrp: target cgroup
 *
 * Returns a pointer to the cgroup node name on success that can
 * be read with probe_read(). NULL on failures.
 */
static inline __attribute__((always_inline)) const char *
get_cgroup_name(const struct cgroup *cgrp)
{
	const char *name;

	if (unlikely(!cgrp))
		return NULL;

	if (BPF_CORE_READ_INTO(&name, cgrp, kn, name) != 0)
		return NULL;

	return name;
}

/**
 * get_cgroup_level() Returns the cgroup level
 * @cgrp: target cgroup
 *
 * Returns the cgroup level, or 0 if it can not be retrieved.
 */
static inline __attribute__((always_inline)) __u32
get_cgroup_level(const struct cgroup *cgrp)
{
	__u32 level = 0;

	probe_read(&level, sizeof(level), _(&cgrp->level));
	return level;
}

/**
 * get_cgroup_id() Returns cgroup id
 * @cgrp: target cgroup
 *
 * Returns the cgroup id of the target cgroup on success, zero on failures.
 */
static inline __attribute__((always_inline)) __u64
get_cgroup_id(const struct cgroup *cgrp)
{
	struct kernfs_node *kn;

	kn = __get_cgroup_kn(cgrp);
	return __get_cgroup_kn_id(kn);
}

/**
 * get_task_cgroup() Returns the accurate or desired cgroup of the css of
 *    current task that we want to operate on.
 * @task: must be current task.
 * @subsys_idx: index of the desired cgroup_subsys_state part of css_set.
 *    Passing a zero as a subsys_idx is fine assuming you want that.
 *
 * Returns the cgroup of the css part of css_set of current task and is
 * indexed at subsys_idx on success, NULL on failures.
 *
 * To get cgroup and kernfs node information we want to operate on the right
 * cgroup hierarchy which is setup by user space. However due to the
 * incompatibility between cgroup v1 and v2; how user space initialize and
 * install cgroup controllers, etc, it can be difficult.
 *
 * Use this helper and pass the css index that you consider accurate and
 * which can be discovered at runtime in user space.
 * Usually it is the 'memory' or 'pids' indexes by reading /proc/cgroups
 * file where each line number is the index starting from zero without
 * counting first comment line.
 */
static inline __attribute__((always_inline)) struct cgroup *
get_task_cgroup(struct task_struct *task, __u32 subsys_idx)
{
	struct cgroup_subsys_state *subsys;
	struct css_set *cgroups;
	struct cgroup *cgrp = NULL;

	probe_read(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if (unlikely(!cgroups))
		return cgrp;

	/* We are interested only in the cpuset, memory or pids controllers
	 * which are indexed at 0, 4 and 11 respectively assuming all controllers
	 * are compiled in.
	 * When we use the controllers indexes we will first discover these indexes
	 * dynamically in user space which will work on all setups from reading
	 * file: /proc/cgroups. If we fail to discover the indexes then passing
	 * a default index zero should be fine assuming we also want that.
	 *
	 * Reference: https://elixir.bootlin.com/linux/v5.19/source/include/linux/cgroup_subsys.h
	 *
	 * Notes:
	 * Newer controllers should be appended at the end. controllers
	 * that are not upstreamed may mess the calculation here
	 * especially if they happen to be before the desired subsys_idx,
	 * we fail.
	 */
	if (unlikely(subsys_idx > pids_cgrp_id))
		return cgrp;

	/* Read css from the passed subsys index to ensure that we operate
	 * on the desired controller. This allows user space to be flexible
	 * and chose the right per cgroup subsystem to use in order to
	 * support as much as workload as possible. It also reduces errors
	 * in a significant way.
	 */
	probe_read(&subsys, sizeof(subsys), _(&cgroups->subsys[subsys_idx]));
	if (unlikely(!subsys))
		return cgrp;

	probe_read(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
	return cgrp;
}

/**
 * get_ancestor_cgroup_id() Returns the ancestor cgroup id of the
 *    passed cgroup that is at level ancestor_level.
 * @cgrp: target cgroup
 * @cgrpfs_ver: Cgroupfs Magic number either Cgroupv1 or Cgroupv2
 * @ancestor_level: the cgroup ancestor level
 *
 * Return id of the cgroup that is the ancestor of the passed cgroup
 * and is at level ancestor_level, or 0 in case the id could not
 * be retrieved or the passed cgroup does not have an ancestor at
 * that level.
 *
 * This helper works for both Cgroupv1 and Cgroupv2. The root
 * cgroup is at ancestor_level zero and each step down the
 * hierarchy increments the level.
 *
 * If ancestor_level == level of passed cgroup, then return value
 * will be the same as that of get_cgroup_id().
 */
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
	else if (level == ancestor_level)
		id = get_cgroup_id(cgrp);

	return id;
}

/**
 * __get_cgrp_tracking_val_heap() Get a cgroup_tracking_val from the
 * tg_cgrps_tracking_heap map while setting its fields.
 */
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

/**
 * __init_cgrp_tracking_val_heap() Initialize a cgroup_tracking_val that is
 * obtained with __get_cgrp_tracking_val_heap(). It will initialize and
 * set the cgroup name too.
 */
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
	int subsys_idx = 0;
	struct cgroup *cgrp;
	__u64 cgrpid_tracker = 0;
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

	if (conf->tg_cgrp_subsys_idx != 0)
		subsys_idx = conf->tg_cgrp_subsys_idx;

	cgrp = get_task_cgroup(task, subsys_idx);
	if (!cgrp)
		return 0;

	level = get_cgroup_level(cgrp);
	if (!level)
		return 0;

	if (level <= conf->tg_cgrp_level) {
		/* Set this as the tracking cgroup of the task since it is before the
		 * tracked level. This means this is probably a Pod or Container level
		 * Anything below will be attached to this tracker
		 */
		cgrpid_tracker = get_cgroup_id(cgrp);
		tracking_level = level;
	} else {
		/* Set the ancestor that is at the tracked level as the tracking cgroup */
		cgrpid_tracker = get_ancestor_cgroup_id(
			cgrp, conf->cgrp_fs_magic, conf->tg_cgrp_level);
		tracking_level = conf->tg_cgrp_level;
	}

	/* Failed to get cgrpid_tracker do nothing. This should never happen */
	if (!cgrpid_tracker)
		return 0;

	execve_val->cgrpid_tracker = cgrpid_tracker;
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
