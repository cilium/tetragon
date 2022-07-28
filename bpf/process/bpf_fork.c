// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_cgroup.h"
#include "bpf_events.h"
#include "environ_conf.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

static inline __attribute__((always_inline)) int
__set_task_cgrpid_tracker(struct tetragon_conf *conf, struct task_struct *task,
			  struct execve_map_value *execve_val)
{
	struct cgroup *cgrp;
	struct cgroup_tracking_value *cgrp_data;
	u32 level = 0, hierarchy_id = 0, tracking_level = 0, flags = 0;

	if (unlikely(!execve_val))
		return 0;

	probe_read(&flags, sizeof(flags), _(&task->flags));
	if (flags & PF_KTHREAD)
		return 0;

	/* Set the tracking cgroup id only if it was not set,
	 * this avoids thread granularity cgroupv1 mess up.
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
		/* Set the ancestor as the tracking cgroup */
		execve_val->cgrpid_tracker = get_ancestor_cgroup_id(cgrp, conf->cgrp_fs_magic,
								    conf->tg_cgrp_level);
		tracking_level = conf->tg_cgrp_level;
	}

	cgrp_data = map_lookup_elem(&tg_cgrps_tracking_map, &execve_val->cgrpid_tracker);
	if (!cgrp_data) {
		/* This was never tracked let's push it here */
		hierarchy_id = get_cgroup_hierarchy_id(cgrp);
		cgrp_data = __get_cgrp_tracking_val_heap(CGROUP_RUNNING, hierarchy_id,
							 tracking_level);
		if (cgrp_data)
			map_update_elem(&tg_cgrps_tracking_map, &execve_val->cgrpid_tracker,
					cgrp_data, BPF_ANY);
	} else if (cgrp_data->state != CGROUP_RUNNING) {
		/* Convert to cgroup running now as we are able to track it */
		cgrp_data->state = CGROUP_RUNNING;
	}

	return 0;
}

__attribute__((section("kprobe/wake_up_new_task"), used)) int
event_wake_up_new_task(struct pt_regs *ctx)
{
	struct execve_map_value *curr, *parent;
	struct task_struct *task, *parent_task;
	struct tetragon_conf *config;
	u32 pid = 0, ppid = 0;
	int zero = 0;

	probe_read(&task, sizeof(task), &ctx->di);
	if (!task)
		return 0;

	probe_read(&pid, sizeof(pid), _(&task->tgid));
	curr = execve_map_get(pid);
	if (!curr)
		return 0;

	/* Cgroup Tracking level */
	config = map_lookup_elem(&tg_conf_map, &zero);
	if (config && config->tg_cgrp_level > 0) {
		/* Set the tracking cgroup ID for the new task */
		__set_task_cgrpid_tracker(config, task, curr);

		/* Let's try to catch parent also if it was not tracked */
		parent_task = (struct task_struct *)get_current_task();
		probe_read(&ppid, sizeof(ppid), _(&parent_task->tgid));

		if (pid != ppid) {
			parent = execve_map_get(ppid);
			if (parent)
				__set_task_cgrpid_tracker(config, parent_task, parent);
		}
	}

	/* generate an EVENT_COMMON_FLAG_CLONE event only once per process */
	if (curr->key.ktime != 0)
		return 0;

	curr->flags = EVENT_COMMON_FLAG_CLONE;
	parent = __event_find_parent(task);
	if (parent) {
		curr->key.pid = pid;
		curr->key.ktime = ktime_get_ns();
		curr->nspid = get_task_pid_vnr();
		curr->binary = parent->binary;
		curr->pkey = parent->key;

		u64 size = sizeof(struct msg_clone_event);
		struct msg_clone_event msg = (struct msg_clone_event){
			.common.op = MSG_OP_CLONE,
			.common.size = size,
			.common.ktime = curr->key.ktime,
			.parent = curr->pkey,
		};
		msg.parent = curr->pkey;
		msg.pid = pid;
		msg.nspid = get_task_pid_vnr();
		msg.flags = curr->flags;
		msg.ktime = curr->key.ktime;

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &msg,
				  size);
	}
	return 0;
}
