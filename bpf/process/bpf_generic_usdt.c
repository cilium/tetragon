// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_USDT

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_usdt_setup_event(void *ctx);
int generic_usdt_process_event(void *ctx);
int generic_usdt_process_filter(void *ctx);
int generic_usdt_filter_arg(void *ctx);
int generic_usdt_actions(void *ctx);
int generic_usdt_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} usdt_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_SETUP] = (void *)&generic_usdt_setup_event,
		[TAIL_CALL_PROCESS] = (void *)&generic_usdt_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_usdt_process_filter,
		[TAIL_CALL_ARGS] = (void *)&generic_usdt_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_usdt_actions,
		[TAIL_CALL_SEND] = (void *)&generic_usdt_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#ifdef __MULTI_KPROBE
#define MAIN "uprobe.multi/generic_usdt"
#else
#define MAIN "uprobe/generic_usdt"
#endif

__attribute__((section((MAIN)), used)) int
generic_usdt_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&usdt_calls);
}

__attribute__((section("uprobe"), used)) int
generic_usdt_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&usdt_calls);
}

__attribute__((section("uprobe"), used)) int
generic_usdt_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&usdt_calls);
}

__attribute__((section("uprobe"), used)) int
generic_usdt_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &usdt_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &usdt_calls, TAIL_CALL_SETUP);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("uprobe"), used)) int
generic_usdt_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&usdt_calls, true);
}

__attribute__((section("uprobe"), used)) int
generic_usdt_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&usdt_calls);
	return 0;
}

__attribute__((section("uprobe"), used)) int
generic_usdt_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_USDT);
}
