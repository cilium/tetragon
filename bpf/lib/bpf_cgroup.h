// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __BPF_CGROUP_
#define __BPF_CGROUP_

#include "bpf_event.h"
#include "bpf_helpers.h"
#include "environ_conf.h"
#include "common.h"
#include "process.h"
#include "../process/types/probe_read_kernel_or_user.h"
#include "bpf_tracing.h"

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
}; // All fields aligned so no 'packed' attribute.

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
}; // All fields aligned so no 'packed' attribute.

/* Map to track cgroups per IDs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64); /* Key is the cgrpid */
	__type(value, struct cgroup_tracking_value);
} tg_cgrps_tracking_map SEC(".maps");

/* Heap used to construct a cgroup_tracking_value */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct cgroup_tracking_value);
} tg_cgrps_tracking_heap SEC(".maps");

/* Heap used to construct a msg_cgroup_event */
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
		probe_read_kernel(&name, sizeof(name), _(&kn->name));

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
		probe_read_kernel(&id, sizeof(id), _(&kn->id));
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
		probe_read_kernel(&kn, sizeof(cgrp->kn), _(&cgrp->kn));

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
 * be read with probe_read_kernel(). NULL on failures.
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

	probe_read_kernel(&level, sizeof(level), _(&cgrp->level));
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
 * @error_flags: error flags that will be ORed to indicate errors on
 *   failures.
 *
 * Returns the cgroup of the css part of css_set of current task and is
 * indexed at subsys_idx on success. NULL on failures, and the error_flags
 * will be ORed to indicate the corresponding error.
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
get_task_cgroup(struct task_struct *task, __u32 subsys_idx, __u32 *error_flags)
{
	struct cgroup_subsys_state *subsys;
	struct css_set *cgroups;
	struct cgroup *cgrp = NULL;

	probe_read_kernel(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if (unlikely(!cgroups)) {
		*error_flags |= EVENT_ERROR_CGROUPS;
		return cgrp;
	}

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
	if (unlikely(subsys_idx > pids_cgrp_id)) {
		*error_flags |= EVENT_ERROR_CGROUP_SUBSYS;
		return cgrp;
	}

	/* Read css from the passed subsys index to ensure that we operate
	 * on the desired controller. This allows user space to be flexible
	 * and chose the right per cgroup subsystem to use in order to
	 * support as much as workload as possible. It also reduces errors
	 * in a significant way.
	 */
	probe_read_kernel(&subsys, sizeof(subsys), _(&cgroups->subsys[subsys_idx]));
	if (unlikely(!subsys)) {
		*error_flags |= EVENT_ERROR_CGROUP_SUBSYS;
		return cgrp;
	}

	probe_read_kernel(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
	if (!cgrp)
		*error_flags |= EVENT_ERROR_CGROUP_SUBSYSCGRP;

	return cgrp;
}

/**
 * __tg_get_current_cgroup_id() Returns the accurate cgroup id of current task.
 * @cgrp: cgroup target of current task.
 * @cgrpfs_ver: Cgroupfs Magic number either Cgroupv1 or Cgroupv2
 *
 * It handles both cgroupv2 and cgroupv1.
 * If @cgrpfs_ver is default cgroupv2 hierarchy, then it uses the bpf
 * helper bpf_get_current_cgroup_id() to retrieve the cgroup id. Otherwise
 * it falls back on using the passed @cgrp
 *
 * Returns the cgroup id of current task on success, zero on failures.
 */
static inline __attribute__((always_inline)) __u64
__tg_get_current_cgroup_id(struct cgroup *cgrp, __u64 cgrpfs_ver)
{
	/*
	 * Try the bpf helper on the default hierarchy if available
	 * and if we are running in unified cgroupv2
	 */
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_get_current_cgroup_id) &&
	    cgrpfs_ver == CGROUP2_SUPER_MAGIC) {
		return get_current_cgroup_id();
	} else {
		return get_cgroup_id(cgrp);
	}
}

/**
 * tg_get_current_cgroup_id() Returns the accurate cgroup id of current task.
 *
 * It works similar to __tg_get_current_cgroup_id, but computes the cgrp if it is needed.
 * Returns the cgroup id of current task on success, zero on failures.
 */
static inline __attribute__((always_inline)) __u64
tg_get_current_cgroup_id()
{
	__u32 error_flags;
	struct cgroup *cgrp;
	__u64 cgrpfs_magic = 0;
	struct task_struct *task;
	struct tetragon_conf *conf;
	int zero = 0, subsys_idx = 0;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf) {
		/* Select which cgroup version */
		cgrpfs_magic = conf->cgrp_fs_magic;
		subsys_idx = conf->tg_cgrp_subsys_idx;
	}

	/*
	 * Try the bpf helper on the default hierarchy if available
	 * and if we are running in unified cgroupv2
	 */
	if (bpf_core_enum_value_exists(enum bpf_func_id,
				       BPF_FUNC_get_current_cgroup_id) &&
	    cgrpfs_magic == CGROUP2_SUPER_MAGIC) {
		return get_current_cgroup_id();
	}

	task = (struct task_struct *)get_current_task();

	// NB: error_flags are ignored for now
	cgrp = get_task_cgroup(task, subsys_idx, &error_flags);
	if (!cgrp)
		return 0;

	return get_cgroup_id(cgrp);
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
		probe_read_kernel_str(&heap->name, KN_NAME_LENGTH - 1, name);

	return heap;
}

#endif // __BPF_CGROUP_
