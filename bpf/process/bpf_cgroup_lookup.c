// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include "bpf_cgroup_lookup.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/proc_task_name"), used)) int
tg_proc_do_cgroup(struct pt_regs *ctx)
{
	struct task_struct *p = (struct task_struct *)PT_REGS_PARM2(ctx);

	__proc_do_cgroup(ctx, p);
	return 0;
}
