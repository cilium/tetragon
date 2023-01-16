// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_exit.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("kprobe/__put_task_struct"), used)) int
event_exit(struct pt_regs *ctx)
{
	struct task_struct *task =
		(struct task_struct *)PT_REGS_PARM1_CORE(ctx);
	__u32 pid, tgid;

	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);

	/* We are only tracking group leaders so if tgid is not
	 * the same as the pid then this is an untracked child
	 * and we can skip the lookup/insert/delete cycle that
	 * would otherwise occur.
	 */
	if (pid == tgid)
		event_exit_send(ctx, tgid, task);
	return 0;
}
