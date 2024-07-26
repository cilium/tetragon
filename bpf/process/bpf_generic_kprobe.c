// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KPROBE

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"
#include "policy_filter.h"
#include "bpf_rate.h"

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
	__uint(max_entries, 1); // will be resized by agent when needed
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

static struct generic_maps maps = {
	.heap = (struct bpf_map_def *)&process_call_heap,
	.calls = (struct bpf_map_def *)&kprobe_calls,
	.config = (struct bpf_map_def *)&config_map,
	.filter = (struct bpf_map_def *)&filter_map,
	.override = (struct bpf_map_def *)&override_tasks,
};

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
	__u64 ktime = ktime_get_ns();
	struct task_struct *task;
	struct msg_k8s kube;

	task = (struct task_struct *)get_current_task();
	__event_get_cgroup_info(task, &kube);

	if (!cgroup_rate(ctx, &kube, ktime))
		return 0;

	return generic_start_process_filter(ctx, &maps);
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
	int ret;

	ret = generic_process_filter((struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&filter_map);
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
	return generic_actions(ctx, &maps);
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
