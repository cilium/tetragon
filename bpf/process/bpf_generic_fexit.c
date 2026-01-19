// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_FEXIT

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_fexit_filter_arg(void *ctx);
int generic_fexit_actions(void *ctx);
int generic_fexit_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__array(values, int(struct pt_regs *));
} fexit_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_ARGS] = (void *)&generic_fexit_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_fexit_actions,
		[TAIL_CALL_SEND] = (void *)&generic_fexit_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#define SECTION_ENTRY "fexit/generic_fexit"
#define SECTION_TAIL  "fexit/generic_fexit_tail"

__attribute__((section(SECTION_ENTRY), used)) int
generic_fexit_event(void *ctx)
{
	__u64 ret;

	get_func_ret(ctx, &ret);
	generic_retprobe(ctx, (struct bpf_map_def *)&fexit_calls, ret);
	return 0;
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fexit_filter_arg(void *ctx)
{
	generic_filter_arg(ctx, (struct bpf_map_def *)&fexit_calls, false);
	return 0;
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fexit_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&fexit_calls);
	return 0;
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fexit_output(void *ctx)
{
	generic_output(ctx, MSG_OP_GENERIC_KPROBE);
	return 0;
}
