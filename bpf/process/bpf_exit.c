// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "bpf_exit.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("tracepoint/sys_exit"), used)) int
event_exit(struct sched_execve_args *ctx)
{
	__u64 pid_tgid;

	pid_tgid = get_current_pid_tgid();

	event_exit_send(ctx, pid_tgid);
	return 0;
}
