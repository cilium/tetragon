// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KPROBE

#include "hubble_msg.h"
#include "bpf_events.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) process_call_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_generic_kprobe),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) kprobe_calls = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 11,
};

struct bpf_map_def __attribute__((section("maps"), used)) override_tasks = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__s32),
	.max_entries = 32768,
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct bpf_map_def __attribute__((section("maps"), used)) filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = FILTER_SIZE,
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct event_config),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) int
generic_kprobe_start_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	struct task_struct *task;
	int i, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;
	/* Initialize selector index to 0 */
	msg->curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->active[i] = 0;
	/* Initialize accept field to reject */
	msg->pass = 0;
	task = (struct task_struct *)get_current_task();
	/* Initialize namespaces to apply filters on them */
	get_namespaces(&(msg->ns), task);
	/* Initialize capabilities to apply filters on them */
	get_caps(&(msg->caps), task);
#ifdef __NS_CHANGES_FILTER
	msg->match_ns = 0;
#endif
#ifdef __CAP_CHANGES_FILTER
	msg->match_cap = 0;
#endif
	/* Tail call into filters. */
	tail_call(ctx, &kprobe_calls, 5);
	return 0;
}

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
__attribute__((section("kprobe/generic_kprobe"), used)) int
generic_kprobe_event(struct pt_regs *ctx)
{
	return generic_kprobe_start_process_filter(ctx);
}

__attribute__((section("kprobe/0"), used)) int
generic_kprobe_process_event0(void *ctx)
{
	return generic_process_event_and_setup(ctx, &process_call_heap,
					       &filter_map, &kprobe_calls,
					       &config_map);
}

__attribute__((section("kprobe/1"), used)) int
generic_kprobe_process_event1(void *ctx)
{
	return generic_process_event1(ctx, &process_call_heap, &filter_map,
				      &kprobe_calls, &config_map);
}

__attribute__((section("kprobe/2"), used)) int
generic_kprobe_process_event2(void *ctx)
{
	return generic_process_event2(ctx, &process_call_heap, &filter_map,
				      &kprobe_calls, &config_map);
}

__attribute__((section("kprobe/3"), used)) int
generic_kprobe_process_event3(void *ctx)
{
	return generic_process_event3(ctx, &process_call_heap, &filter_map,
				      &kprobe_calls, &config_map);
}

__attribute__((section("kprobe/4"), used)) int
generic_kprobe_process_event4(void *ctx)
{
	return generic_process_event4(ctx, &process_call_heap, &filter_map,
				      &kprobe_calls, &config_map);
}

__attribute__((section("kprobe/5"), used)) int
generic_kprobe_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(msg, &filter_map, &process_call_heap);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &kprobe_calls, 5);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &kprobe_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("kprobe/6"), used)) int
generic_kprobe_filter_arg1(void *ctx)
{
	return filter_read_arg(ctx, 0, &process_call_heap, &filter_map,
			       &kprobe_calls, &override_tasks, &config_map);
}

__attribute__((section("kprobe/7"), used)) int
generic_kprobe_filter_arg2(void *ctx)
{
	return filter_read_arg(ctx, 1, &process_call_heap, &filter_map,
			       &kprobe_calls, &override_tasks, &config_map);
}

__attribute__((section("kprobe/8"), used)) int
generic_kprobe_filter_arg3(void *ctx)
{
	return filter_read_arg(ctx, 2, &process_call_heap, &filter_map,
			       &kprobe_calls, &override_tasks, &config_map);
}

__attribute__((section("kprobe/9"), used)) int
generic_kprobe_filter_arg4(void *ctx)
{
	return filter_read_arg(ctx, 3, &process_call_heap, &filter_map,
			       &kprobe_calls, &override_tasks, &config_map);
}

__attribute__((section("kprobe/10"), used)) int
generic_kprobe_filter_arg5(void *ctx)
{
	return filter_read_arg(ctx, 4, &process_call_heap, &filter_map,
			       &kprobe_calls, &override_tasks, &config_map);
}

__attribute__((section("kprobe/override"), used)) int
generic_kprobe_override(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error;

	error = map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	override_return(ctx, *error);
	map_delete_elem(&override_tasks, &id);
	return 0;
}
