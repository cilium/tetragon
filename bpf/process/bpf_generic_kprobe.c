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

#define KPROBE_TAILCALL_SETUP_AND_A0   0 /* A0: retrieve arguments and handle first arg */
#define KPROBE_TAILCALL_A1	       1 /* A1-A4: handle rest of the args */
#define KPROBE_TAILCALL_A2	       2
#define KPROBE_TAILCALL_A3	       3
#define KPROBE_TAILCALL_A4	       4
#define KPROBE_TAILCALL_PROCESS_FILTER 5 /* check process filters */
#define KPROBE_TAILCALL_SEL0_FILTER    6 /* selector filters */
#define KPROBE_TAILCALL_SEL1_FILTER    7
#define KPROBE_TAILCALL_SEL2_FILTER    8
#define KPROBE_TAILCALL_SEL3_FILTER    9
#define KPROBE_TAILCALL_SEL4_FILTER    10
#define KPROBE_TAILCALL_POLICY_FILTER  11

#define str(x)		    #x
#define KPROBE_TAILCALL(nr) __attribute__((section("kprobe/" str(nr)), used))

_Static_assert(KPROBE_TAILCALL_SEL0_FILTER == MIN_FILTER_TAILCALL, "selector tailcall mismatch");
_Static_assert(KPROBE_TAILCALL_SEL4_FILTER == MAX_FILTER_TAILCALL, "selector tailcall mismatch");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 12);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} kprobe_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, __s32);
} override_tasks SEC(".maps");

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES_CONFIG);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES_CONFIG);
	__type(key, int);
	__type(value, struct event_config);
} config_map SEC(".maps");

static inline __attribute__((always_inline)) int
generic_kprobe_start_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	struct event_config *conf;
	struct task_struct *task;
	int i, zero = 0, tcall;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;
	/* Initialize selector index to 0 */
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	/* Initialize accept field to reject */
	msg->sel.pass = 0;
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
	conf = setup_index(ctx, msg, (struct bpf_map_def *)&config_map);
	if (!conf)
		return 0;
	tcall = conf->policy_id ? KPROBE_TAILCALL_POLICY_FILTER : KPROBE_TAILCALL_PROCESS_FILTER;
	/* Tail call into filters. */
	tail_call(ctx, &kprobe_calls, tcall);
	return 0;
}

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/generic_kprobe"
#else
#define MAIN "kprobe/generic_kprobe"
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

KPROBE_TAILCALL(KPROBE_TAILCALL_SETUP_AND_A0)
int generic_kprobe_process_event0(void *ctx)
{
	return generic_process_event_and_setup(
		ctx, (struct bpf_map_def *)&process_call_heap,
		(struct bpf_map_def *)&filter_map,
		(struct bpf_map_def *)&kprobe_calls,
		(struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_A1)
int generic_kprobe_process_event1(void *ctx)
{
	return generic_process_event1(ctx,
				      (struct bpf_map_def *)&process_call_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&kprobe_calls,
				      (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_A2)
int generic_kprobe_process_event2(void *ctx)
{
	return generic_process_event2(ctx,
				      (struct bpf_map_def *)&process_call_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&kprobe_calls,
				      (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_A3)
int generic_kprobe_process_event3(void *ctx)
{
	return generic_process_event3(ctx,
				      (struct bpf_map_def *)&process_call_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&kprobe_calls,
				      (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_A4)
int generic_kprobe_process_event4(void *ctx)
{
	return generic_process_event4(ctx,
				      (struct bpf_map_def *)&process_call_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&kprobe_calls,
				      (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_PROCESS_FILTER)
int generic_kprobe_process_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(&msg->sel, &msg->current, &msg->ns,
				     &msg->caps, &filter_map, msg->idx);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &kprobe_calls, KPROBE_TAILCALL_PROCESS_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &kprobe_calls, KPROBE_TAILCALL_SETUP_AND_A0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

KPROBE_TAILCALL(KPROBE_TAILCALL_SEL0_FILTER)
int generic_kprobe_filter_arg1(void *ctx)
{
	return filter_read_arg(ctx, 0, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks,
			       (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_SEL1_FILTER)
int generic_kprobe_filter_arg2(void *ctx)
{
	return filter_read_arg(ctx, 1, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks,
			       (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_SEL2_FILTER)
int generic_kprobe_filter_arg3(void *ctx)
{
	return filter_read_arg(ctx, 2, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks,
			       (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_SEL3_FILTER)
int generic_kprobe_filter_arg4(void *ctx)
{
	return filter_read_arg(ctx, 3, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks,
			       (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_SEL4_FILTER)
int generic_kprobe_filter_arg5(void *ctx)
{
	return filter_read_arg(ctx, 4, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&kprobe_calls,
			       (struct bpf_map_def *)&override_tasks,
			       (struct bpf_map_def *)&config_map);
}

KPROBE_TAILCALL(KPROBE_TAILCALL_POLICY_FILTER)
int generic_kprobe_policy_filter(void *ctx)
{
	// TODO: policy filter
	tail_call(ctx, &kprobe_calls, KPROBE_TAILCALL_PROCESS_FILTER);
	return 0;
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
