// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_UPROBE

#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} uprobe_calls SEC(".maps");

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_config);
} config_map SEC(".maps");

static inline __attribute__((always_inline)) int
generic_uprobe_start_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	struct event_config *config;
	struct task_struct *task;
	int i, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;
	/* Initialize selector index to 0 */
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	/* Initialize accept field to reject */
	msg->sel.pass = false;
	msg->tailcall_index_process = 0;
	msg->tailcall_index_selector = 0;
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
	msg->idx = get_index(ctx);
	// setup index and function id
	config = map_lookup_elem(&config_map, &msg->idx);
	if (!config)
		return 0;
	msg->func_id = config->func_id;
	msg->retprobe_id = 0;
	/* Tail call into filters. */
	tail_call(ctx, &uprobe_calls, TAIL_CALL_FILTER);
	return 0;
}

#ifdef __MULTI_KPROBE
#define MAIN "uprobe.multi/generic_uprobe"
#else
#define MAIN "uprobe/generic_uprobe"
#endif

__attribute__((section((MAIN)), used)) int
generic_uprobe_event(struct pt_regs *ctx)
{
	return generic_uprobe_start_process_filter(ctx);
}

__attribute__((section("uprobe/0"), used)) int
generic_uprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(
		ctx, (struct bpf_map_def *)&process_call_heap,
		(struct bpf_map_def *)&uprobe_calls,
		(struct bpf_map_def *)&config_map, 0);
}

__attribute__((section("uprobe/1"), used)) int
generic_uprobe_process_event(void *ctx)
{
	return generic_process_event(ctx,
				     (struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&uprobe_calls,
				     (struct bpf_map_def *)&config_map, 0);
}

__attribute__((section("uprobe/2"), used)) int
generic_uprobe_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(&msg->sel, &msg->current, &msg->ns,
				     &msg->caps, &filter_map, msg->idx);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &uprobe_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("uprobe/3"), used)) int
generic_uprobe_filter_arg(void *ctx)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&uprobe_calls,
			       (struct bpf_map_def *)&config_map,
			       true);
}

__attribute__((section("uprobe/4"), used)) int
generic_uprobe_actions(void *ctx)
{
	return generic_actions(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&uprobe_calls,
			       (void *)0);
}

__attribute__((section("uprobe/5"), used)) int
generic_uprobe_output(void *ctx)
{
	return generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_UPROBE);
}
