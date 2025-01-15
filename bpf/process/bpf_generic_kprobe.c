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
#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_kprobe_setup_event(void *ctx);
int generic_kprobe_process_event(void *ctx);
int generic_kprobe_process_filter(void *ctx);
int generic_kprobe_filter_arg(void *ctx);
int generic_kprobe_actions(void *ctx);
int generic_kprobe_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} kprobe_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&generic_kprobe_setup_event,
		[1] = (void *)&generic_kprobe_process_event,
		[2] = (void *)&generic_kprobe_process_filter,
		[3] = (void *)&generic_kprobe_filter_arg,
		[4] = (void *)&generic_kprobe_actions,
		[5] = (void *)&generic_kprobe_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

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
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&kprobe_calls);
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&kprobe_calls);
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&kprobe_calls);
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	switch (ret) {
	case PFILTER_CONTINUE:
		tail_call(ctx, &kprobe_calls, TAIL_CALL_FILTER);
	case PFILTER_CURR_NOT_FOUND:
	case PFILTER_ACCEPT:
		tail_call(ctx, &kprobe_calls, TAIL_CALL_SETUP);
	}
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&kprobe_calls, true);
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&kprobe_calls);
	return 0;
}

__attribute__((section("kprobe"), used)) int
generic_kprobe_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_KPROBE);
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
