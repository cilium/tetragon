// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KRETPROBE

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"
#include "generic_calls.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

int generic_retkprobe_filter_arg(struct pt_regs *ctx);
int generic_retkprobe_actions(struct pt_regs *ctx);
int generic_retkprobe_output(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 6);
	__uint(key_size, sizeof(__u32));
	__array(values, int(struct pt_regs *));
} retkprobe_calls SEC(".maps") = {
	.values = {
		[3] = (void *)&generic_retkprobe_filter_arg,
		[4] = (void *)&generic_retkprobe_actions,
		[5] = (void *)&generic_retkprobe_output,
	},
};

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

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

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/generic_retkprobe"
#else
#define MAIN "kprobe/generic_retkprobe"
#endif

static struct generic_maps maps = {
	.heap = (struct bpf_map_def *)&process_call_heap,
	.calls = (struct bpf_map_def *)&retkprobe_calls,
	.filter = (struct bpf_map_def *)&filter_map,
	.config = (struct bpf_map_def *)&config_map,
	.data = (struct bpf_map_def *)data_heap_ptr,
};

__attribute__((section((MAIN)), used)) int
BPF_KRETPROBE(generic_retkprobe_event, unsigned long ret)
{
	return generic_retkprobe(ctx, &maps, ret);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_filter_arg)
{
	return filter_read_arg(ctx, &maps, false);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_actions)
{
	generic_actions(ctx, &maps);
	return 0;
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_output)
{
	return generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_KPROBE);
}
