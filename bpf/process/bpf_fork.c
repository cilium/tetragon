// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/wake_up_new_task"), used)) int
event_wake_up_new_task(struct pt_regs *ctx)
{
	struct execve_map_value *curr, *parent;
	struct task_struct *task;
	u32 pid = 0;

	probe_read(&task, sizeof(task), &ctx->di);
	if (!task)
		return 0;

	probe_read(&pid, sizeof(pid), _(&task->tgid));
	curr = execve_map_get(pid);
	if (!curr)
		return 0;

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
