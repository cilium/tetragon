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
#include "pfilter.h"
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

int generic_retkprobe_filter_arg(void *ctx);
int generic_retkprobe_actions(void *ctx);
int generic_retkprobe_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 6);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} retkprobe_calls SEC(".maps") = {
	.values = {
		[3] = (void *)&generic_retkprobe_filter_arg,
		[4] = (void *)&generic_retkprobe_actions,
		[5] = (void *)&generic_retkprobe_output,
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

__attribute__((section(("kprobe.session/generic_kprobe")), used)) int
generic_kprobe_event(struct pt_regs *ctx)
{
	if (bpf_session_is_return()) {
		return generic_retkprobe(ctx, (struct bpf_map_def *)&retkprobe_calls,
					 PT_REGS_RC(ctx));
	}

	generic_start_process_filter(ctx, (struct bpf_map_def *)&kprobe_calls);
	return 1; /* kill return probe */
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_setup_event(void *ctx)
{
	generic_process_event_and_setup(ctx, (struct bpf_map_def *)&kprobe_calls);
	return 1; /* kill return probe */
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_process_event(void *ctx)
{
	generic_process_event(ctx, (struct bpf_map_def *)&kprobe_calls);
	return 1; /* kill return probe */
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &kprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &kprobe_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return ret == PFILTER_REJECT ? 1 : 0;
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_filter_arg(void *ctx)
{
	generic_filter_arg(ctx, (struct bpf_map_def *)&kprobe_calls, true);
	return 1; /* kill return probe */
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&kprobe_calls, true);
	return 1; /* kill return probe */
}

__attribute__((section("kprobe.session"), used)) int
generic_kprobe_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_KPROBE);
}

__attribute__((section("kprobe.session"), used)) int
generic_retkprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&retkprobe_calls, false);
}

__attribute__((section("kprobe.session"), used)) int
generic_retkprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&retkprobe_calls, false);
	return 0;
}

__attribute__((section("kprobe.session"), used)) int
generic_retkprobe_output(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret = 0, zero = 0;

	generic_output(ctx, MSG_OP_GENERIC_KPROBE);

	/* make sure we want to trigger return probe */
	msg = map_lookup_elem(&process_call_heap, &zero);
	ret = msg && msg->has_return;

	asm volatile("%[ret] &= 0x1;\n"
		     : [ret] "+r"(ret));
	return ret;
}
