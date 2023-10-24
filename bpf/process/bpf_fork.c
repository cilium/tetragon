// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "bpf_event.h"
#include "bpf_cgroup.h"
#include "bpf_task.h"
#include "environ_conf.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/wake_up_new_task"), used)) int
BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
	struct execve_map_value *curr, *parent;
	u32 tgid = 0, error_flags = 0;

	if (!task)
		return 0;

	tgid = BPF_CORE_READ(task, tgid);

	curr = execve_map_get(tgid);
	if (!curr)
		return 0;

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
			/**
			 * Per thread tracking rules TID == PID :
			 *  Since we generate one event per thread group, then when this task
			 *  wakes up it will be the only one in the thread group, and it is
			 *  the leader. Ensure to pass TID to user space.
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
