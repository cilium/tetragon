// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "bpf_event.h"
#include "bpf_cgroup.h"
#include "bpf_task.h"
#include "environ_conf.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/wake_up_new_task"), used)) int
BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
	struct execve_map_value *curr, *parent;
	struct task_struct *current_task;
	struct tetragon_conf *config;
	u32 tgid = 0, ppid = 0, error_flags = 0;
	int zero = 0;

	if (!task)
		return 0;

	tgid = BPF_CORE_READ(task, tgid);

	curr = execve_map_get(tgid);
	if (!curr)
		return 0;

	/* Cgroup environment */
	config = map_lookup_elem(&tg_conf_map, &zero);
	if (config) {
		/* Set the tracking cgroup ID for the new task if not already set */
		__set_task_cgrpid_tracker(config, task, curr, &error_flags);

		/* Let's try to catch current or "parent" if it was not tracked */
		current_task = (struct task_struct *)get_current_task();
		probe_read(&ppid, sizeof(ppid), _(&current_task->tgid));
		/* If they share same thread group nothing todo... */
		if (tgid != ppid) {
			parent = execve_map_get_noinit(ppid);
			if (parent)
				__set_task_cgrpid_tracker(config, current_task,
							  parent, &error_flags);
		}
	}

	/* Generate an EVENT_COMMON_FLAG_CLONE event once per process,
	 * that is, thread group.
	 */
	if (curr->key.ktime != 0)
		return 0;

	curr->flags = EVENT_COMMON_FLAG_CLONE;
	parent = __event_find_parent(task);
	if (parent) {
		curr->key.pid = tgid;
		curr->key.ktime = ktime_get_ns();
		curr->nspid = get_task_pid_vnr();
		curr->binary = parent->binary;
		curr->pkey = parent->key;

		u64 size = sizeof(struct msg_clone_event);
		struct msg_clone_event msg = {
			.common.op = MSG_OP_CLONE,
			.common.size = size,
			.common.ktime = curr->key.ktime,
			.parent = curr->pkey,
			.tgid = curr->key.pid,
			/* Since we generate one event per thread group, then when
			 * the task wakes up, there will be only one thread here:
			 * the thread group leader. Pass its thread id to user-space.
			 */
			.tid = BPF_CORE_READ(task, pid),
			.ktime = curr->key.ktime,
			.nspid = curr->nspid,
			.flags = curr->flags,
		};

		/* Last: set any encountered error when setting cgroup info */
		msg.flags |= error_flags;

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &msg,
				  size);
	}
	return 0;
}
