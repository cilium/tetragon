// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"

#define GENERIC_TRACEPOINT

#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "policy_filter.h"
#include "syscall64.h"

int generic_tracepoint_process_event(void *ctx);
int generic_tracepoint_filter(void *ctx);
int generic_tracepoint_arg(void *ctx);
int generic_tracepoint_actions(void *ctx);
int generic_tracepoint_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} tp_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_PROCESS] = (void *)&generic_tracepoint_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_tracepoint_filter,
		[TAIL_CALL_ARGS] = (void *)&generic_tracepoint_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_tracepoint_actions,
		[TAIL_CALL_SEND] = (void *)&generic_tracepoint_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

__attribute__((section("tracepoint/generic_tracepoint"), used)) int
generic_tracepoint_event(struct generic_tracepoint_event_arg *ctx)
{
	struct msg_generic_kprobe *msg;
	struct task_struct *task;
	struct event_config *config;
	int zero = 0, i;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	config = map_lookup_elem(&config_map, &zero);
	if (!config)
		return 0;

	/* check policy filter */
	if (!policy_filter_check(config->policy_id))
		return 0;

	/* Tail call into filters. */
	msg->idx = 0;
	msg->func_id = config->func_id;
	msg->retprobe_id = 0;

	generic_process_init(msg, MSG_OP_GENERIC_TRACEPOINT, config);

	msg->common.op = MSG_OP_GENERIC_TRACEPOINT;
	msg->sel.curr = 0;
	msg->tailcall_index_process = 0;
	msg->tailcall_index_selector = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	msg->sel.pass = false;
	task = (struct task_struct *)get_current_task();
	/* Initialize namespaces to apply filters on them */
	get_namespaces(&msg->ns, task);
	/* Initialize capabilities to apply filters on them */
	get_current_subj_caps(&msg->caps, task);
#ifdef __NS_CHANGES_FILTER
	msg->sel.match_ns = 0;
#endif
#ifdef __CAP_CHANGES_FILTER
	msg->sel.match_cap = 0;
#endif
	msg->common.flags = 0;
	tail_call(ctx, &tp_calls, TAIL_CALL_FILTER);
	return 0;
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&tp_calls);
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &tp_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &tp_calls, TAIL_CALL_PROCESS);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&tp_calls, true);
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&tp_calls);
	return 0;
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_TRACEPOINT);
}

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
