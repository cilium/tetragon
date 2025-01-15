// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_UPROBE

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_uprobe_setup_event(void *ctx);
int generic_uprobe_process_event(void *ctx);
int generic_uprobe_process_filter(void *ctx);
int generic_uprobe_filter_arg(void *ctx);
int generic_uprobe_actions(void *ctx);
int generic_uprobe_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} uprobe_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&generic_uprobe_setup_event,
		[1] = (void *)&generic_uprobe_process_event,
		[2] = (void *)&generic_uprobe_process_filter,
		[3] = (void *)&generic_uprobe_filter_arg,
		[4] = (void *)&generic_uprobe_actions,
		[5] = (void *)&generic_uprobe_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#ifdef __MULTI_KPROBE
#define MAIN "uprobe.multi/generic_uprobe"
#else
#define MAIN "uprobe/generic_uprobe"
#endif

__attribute__((section((MAIN)), used)) int
generic_uprobe_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_SETUP);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&uprobe_calls, true);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&uprobe_calls);
	return 0;
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_UPROBE);
}
