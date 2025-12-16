// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_RAWTP

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_rawtp_setup_event(void *ctx);
int generic_rawtp_process_event(void *ctx);
int generic_rawtp_process_filter(void *ctx);
int generic_rawtp_filter_arg(void *ctx);
int generic_rawtp_actions(void *ctx);
int generic_rawtp_output(void *ctx);
int generic_rawtp_path(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} tp_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_SETUP] = (void *)&generic_rawtp_setup_event,
		[TAIL_CALL_PROCESS] = (void *)&generic_rawtp_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_rawtp_process_filter,
		[TAIL_CALL_ARGS] = (void *)&generic_rawtp_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_rawtp_actions,
		[TAIL_CALL_SEND] = (void *)&generic_rawtp_output,
#ifndef __V61_BPF_PROG
		[TAIL_CALL_PATH] = (void *)&generic_rawtp_path,
#endif
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

/* Generic kprobe pseudocode is the following
 *
 *  filter_pids -> drop if no matches
 *  filter_namespaces -> drop if no matches
 *  filter_capabilities -> drop if no matches
 *  filter_namespace_changes -> drop if no matches
 *  filter_capability_changes -> drop if no matches
 *  copy arguments buffer
 *  filter selectors -> drop if no matches
 *  generate ring buffer event
 *
 * First we filter by pids this allows us to quickly drop events
 * that are not relevant. This is helpful if we end up copying
 * large string values.
 *
 * Then we copy arguments then run full selectors logic. We keep
 * track of pids that passed initial filter so we avoid running
 * pid filters twice.
 *
 * For 4.19 kernels we have to use the tail call infrastructure
 * to get below 4k insns. For 5.x+ kernels with 1m.insns its not
 * an issue.
 */
__attribute__((section("raw_tp/generic_tracepoint"), used)) int
generic_rawtp_event(void *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&tp_calls);
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&tp_calls);
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&tp_calls, __READ_ARG_ALL);
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &tp_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &tp_calls, TAIL_CALL_SETUP);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&tp_calls, true);
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&tp_calls);
	return 0;
}

__attribute__((section("raw_tp"), used)) int
generic_rawtp_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_TRACEPOINT);
}

#ifndef __V61_BPF_PROG
__attribute__((section("raw_tp"), used)) int
generic_rawtp_path(void *ctx)
{
	return generic_path(ctx, (struct bpf_map_def *)&tp_calls);
}
#endif
