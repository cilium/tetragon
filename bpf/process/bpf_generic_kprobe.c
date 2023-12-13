// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KPROBE

#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"
#include "policy_filter.h"

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
} kprobe_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, __s32);
} override_tasks SEC(".maps");

#ifdef __LARGE_BPF_PROG
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");
#define data_heap_ptr &data_heap
#else
#define data_heap_ptr 0
#endif

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
generic_kprobe_start_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	struct event_config *config;
	struct task_struct *task;
	int i, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	/* setup index, check policy filter, and setup function id */
	msg->idx = get_index(ctx);
	config = map_lookup_elem(&config_map, &msg->idx);
	if (!config)
		return 0;
	if (!generic_process_filter_binary(config))
		return 0;
	if (!policy_filter_check(config->policy_id))
		return 0;
	msg->func_id = config->func_id;

	/* Initialize selector index to 0 */
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	/* Initialize accept field to reject */
	msg->sel.pass = false;
	msg->filter_tailcall_index = 0;
	task = (struct task_struct *)get_current_task();
	/* Initialize namespaces to apply filters on them */
	get_namespaces(&(msg->ns), task);
	/* Initialize capabilities to apply filters on them */
	get_current_subj_caps(&msg->caps, task);
#ifdef __NS_CHANGES_FILTER
	msg->sel.match_ns = 0;
#endif
#ifdef __CAP_CHANGES_FILTER
	msg->sel.match_cap = 0;
#endif

	/* Tail call into filters. */
	tail_call(ctx, &kprobe_calls, TAIL_CALL_FILTER);
	return 0;
}

#ifdef __MULTI_KPROBE
#define MAIN	 "kprobe.multi/generic_kprobe"
#define OVERRIDE "kprobe.multi/generic_kprobe_override"
#else
#define MAIN	 "kprobe/generic_kprobe"
#define OVERRIDE "kprobe/generic_kprobe_override"
#endif

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
__attribute__((section((MAIN)), used)) int
generic_kprobe_event(struct pt_regs *ctx)
{
	return generic_kprobe_start_process_filter(ctx);
}

__attribute__((section("kprobe/0"), used)) int
generic_kprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(
		ctx, (struct bpf_map_def *)&process_call_heap,
		(struct bpf_map_def *)&kprobe_calls,
		(struct bpf_map_def *)&config_map,
		(struct bpf_map_def *)data_heap_ptr);
}

__attribute__((section("kprobe/1"), used)) int
generic_kprobe_process_event(void *ctx)
{
	return generic_process_event(ctx,
				     (struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&kprobe_calls,
				     (struct bpf_map_def *)&config_map,
				     (struct bpf_map_def *)data_heap_ptr);
}

__attribute__((section("kprobe/2"), used)) int
generic_kprobe_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(&msg->sel, &msg->current, &msg->ns,
				     &msg->caps, &filter_map, msg->idx);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &kprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &kprobe_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("kprobe/3"), used)) int
generic_kprobe_filter_arg(void *ctx)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&config_map,
			       true);
}

__attribute__((section("kprobe/4"), used)) int
generic_kprobe_actions(void *ctx)
{
	return generic_actions(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks);
}

__attribute__((section("kprobe/5"), used)) int
generic_kprobe_output(void *ctx)
{
	return generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_KPROBE);
}

__attribute__((section(OVERRIDE), used)) int
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

/* Putting security_task_prctl in here to pass contrib/verify/verify.sh test,
 * in normal run the function is set by tetragon dynamically.
 */
__attribute__((section("fmod_ret/security_task_prctl"), used)) long
generic_fmodret_override(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error;

	error = map_lookup_elem(&override_tasks, &id);
	if (!error)
		return 0;

	map_delete_elem(&override_tasks, &id);
	return (long)*error;
}
