// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KRETPROBE

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_retkprobe_filter_arg(struct pt_regs *ctx);
int generic_retkprobe_actions(struct pt_regs *ctx);
int generic_retkprobe_output(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__array(values, int(struct pt_regs *));
} retkprobe_calls SEC(".maps") = {
	.values = {
		[3] = (void *)&generic_retkprobe_filter_arg,
		[4] = (void *)&generic_retkprobe_actions,
		[5] = (void *)&generic_retkprobe_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/generic_retkprobe"
#else
#define MAIN "kprobe/generic_retkprobe"
#endif

__attribute__((section((MAIN)), used)) int
BPF_KRETPROBE(generic_retkprobe_event, unsigned long ret)
{
	return generic_retkprobe(ctx, (struct bpf_map_def *)&retkprobe_calls, ret);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_filter_arg)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&retkprobe_calls, false);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_actions)
{
	generic_actions(ctx, (struct bpf_map_def *)&retkprobe_calls);
	return 0;
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_output)
{
	return generic_output(ctx, MSG_OP_GENERIC_KPROBE);
}
