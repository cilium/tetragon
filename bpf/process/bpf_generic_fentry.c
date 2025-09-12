// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_FENTRY

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_fentry_setup_event(void *ctx);
int generic_fentry_process_event(void *ctx);
int generic_fentry_process_filter(void *ctx);
int generic_fentry_filter_arg(void *ctx);
int generic_fentry_actions(void *ctx);
int generic_fentry_output(void *ctx);
int generic_fentry_path(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} fentry_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_SETUP] = (void *)&generic_fentry_setup_event,
		[TAIL_CALL_PROCESS] = (void *)&generic_fentry_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_fentry_process_filter,
		[TAIL_CALL_ARGS] = (void *)&generic_fentry_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_fentry_actions,
		[TAIL_CALL_SEND] = (void *)&generic_fentry_output,
#ifndef __V61_BPF_PROG
		[TAIL_CALL_PATH] = (void *)&generic_fentry_path,
#endif
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#define SECTION_ENTRY "fentry/generic_fentry"
#define SECTION_TAIL  "fentry/generic_fentry_tail"

__attribute__((section((SECTION_ENTRY)), used)) int
generic_fentry_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&fentry_calls);
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&fentry_calls);
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&fentry_calls);
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &fentry_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &fentry_calls, TAIL_CALL_SETUP);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&fentry_calls, true);
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&fentry_calls);
	return 0;
}

__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_KPROBE);
}

#ifndef __V61_BPF_PROG
__attribute__((section(SECTION_TAIL), used)) int
generic_fentry_path(void *ctx)
{
	return generic_path(ctx, (struct bpf_map_def *)&fentry_calls);
}
#endif
