// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include "vmlinux.h"

#include "api.h"
#include "bpf_tracing.h"
#include "bpf_cgroup_lookup.h"

char _license[] __attribute__((section("license"), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

SEC("fentry/proc_task_name")
int BPF_PROG(tg_proc_do_cgroup, struct seq_file *m, struct task_struct *p, bool escape)
{
	__proc_do_cgroup(ctx, p);
	return 0;
}
