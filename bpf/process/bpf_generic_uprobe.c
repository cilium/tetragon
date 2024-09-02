// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_UPROBE

#include "compiler.h"
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

int generic_uprobe_setup_event(void *ctx);
int generic_uprobe_process_event(void *ctx);
int generic_uprobe_process_filter(void *ctx);
int generic_uprobe_filter_arg(void *ctx);
int generic_uprobe_actions(void *ctx);
int generic_uprobe_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} uprobe_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&generic_uprobe_setup_event,
		[1] = (void *)&generic_uprobe_process_event,
		[2] = (void *)&generic_uprobe_process_filter,
		[3] = (void *)&generic_uprobe_filter_arg,
		[4] = (void *)&generic_uprobe_actions,
		[5] = (void *)&generic_uprobe_output,
	},
};

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
	.calls = (struct bpf_map_def *)&uprobe_calls,
	.config = (struct bpf_map_def *)&config_map,
	.filter = (struct bpf_map_def *)&filter_map,
};

#ifdef __MULTI_KPROBE
#define MAIN "uprobe.multi/generic_uprobe"
#else
#define MAIN "uprobe/generic_uprobe"
#endif

__attribute__((section((MAIN)), used)) int
generic_uprobe_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, &maps);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(
		ctx, (struct bpf_map_def *)&process_call_heap,
		(struct bpf_map_def *)&uprobe_calls,
		(struct bpf_map_def *)&config_map, 0);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_process_event(void *ctx)
{
	return generic_process_event(ctx,
				     (struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&uprobe_calls,
				     (struct bpf_map_def *)&config_map, 0);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter((struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&filter_map);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &uprobe_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_filter_arg(void *ctx)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&uprobe_calls,
			       (struct bpf_map_def *)&config_map,
			       true);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_actions(void *ctx)
{
	return generic_actions(ctx, &maps);
}

__attribute__((section("uprobe"), used)) int
generic_uprobe_output(void *ctx)
{
	return generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_UPROBE);
}
