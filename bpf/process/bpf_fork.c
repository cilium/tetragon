// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("kprobe/wake_up_new_task")), used)) int
event_wake_up_new_task(struct pt_regs *ctx)
{
	struct execve_map_value *curr;
	struct task_struct *task;
	u32 pid = 0;

	probe_read(&task, sizeof(task), &ctx->di);
	if (!task)
		return 0;

	probe_read(&pid, sizeof(pid), _(&task->tgid));
	curr = execve_map_get(pid);
	if (!curr)
		return 0;
	curr->flags = EVENT_COMMON_FLAG_CLONE;
	return 0;
}
