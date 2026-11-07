// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_URETPROBE

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"
#include "regs.h"

// Keep pending return overrides separate from entry register assignments.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __s32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} return_override SEC(".maps");

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_retuprobe_filter_arg(struct pt_regs *ctx);
int generic_retuprobe_filter_arg_2(struct pt_regs *ctx);
int generic_retuprobe_actions(struct pt_regs *ctx);
int generic_retuprobe_output(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(struct pt_regs *));
} retuprobe_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_ARGS] = (void *)&generic_retuprobe_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_retuprobe_actions,
		[TAIL_CALL_SEND] = (void *)&generic_retuprobe_output,
#ifndef __LARGE_BPF_PROG
		[TAIL_CALL_ARGS_2] = (void *)&generic_retuprobe_filter_arg_2,
#endif
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#ifdef __MULTI_KPROBE
#define MAIN	"uprobe.multi/generic_retuprobe"
#define COMMON	"uprobe.multi"
#define OFFLOAD "uprobe.multi.s/generic_retuprobe"
#else
#define MAIN	"uprobe/generic_retuprobe"
#define COMMON	"uprobe"
#define OFFLOAD "uprobe.s/generic_retuprobe"
#endif

__attribute__((section((MAIN)), used)) int
BPF_KRETPROBE(generic_retuprobe_event, unsigned long ret)
{
	return heap_dtor(generic_retprobe(ctx, (struct bpf_map_def *)&retuprobe_calls, ret));
}

#ifdef __LARGE_BPF_PROG
__attribute__((section(COMMON), used)) int
BPF_KRETPROBE(generic_retuprobe_filter_arg)
{
	return heap_dtor(generic_filter_arg(ctx, (struct bpf_map_def *)&retuprobe_calls, false,
					    __FILTER_ARG_ALL));
}
#else
__attribute__((section(COMMON), used)) int
BPF_KRETPROBE(generic_retuprobe_filter_arg)
{
	return heap_dtor(generic_filter_arg(ctx, (struct bpf_map_def *)&retuprobe_calls, false,
					    __FILTER_ARG_1));
}

__attribute__((section(COMMON), used)) int
BPF_KRETPROBE(generic_retuprobe_filter_arg_2)
{
	return heap_dtor(generic_filter_arg(ctx, (struct bpf_map_def *)&retuprobe_calls, false,
					    __FILTER_ARG_2));
}
#endif

__attribute__((section(COMMON), used)) int
BPF_KRETPROBE(generic_retuprobe_actions)
{
	heap_dtor(generic_actions(ctx, (struct bpf_map_def *)&retuprobe_calls));
	return 0;
}

__attribute__((section(COMMON), used)) int
BPF_KRETPROBE(generic_retuprobe_output)
{
	return heap_dtor(generic_output(ctx, MSG_OP_GENERIC_UPROBE));
}

// The non-sleepable action queues a value only after return filters match.
// At return, leave the caller's instruction pointer and stack unchanged.
__attribute__((section(OFFLOAD), used)) int
generic_sleepable_offload(struct pt_regs *ctx)
{
	__u64 id = get_current_pid_tgid();
	__s32 *pending, value;

	pending = map_lookup_elem(&return_override, &id);
	if (!pending)
		return 0;
	value = *pending;
	map_delete_elem(&return_override, &id);
#if defined(__TARGET_ARCH_x86)
	write_reg(ctx, offsetof(struct pt_regs, ax), 8, (__s64)value);
#elif defined(__TARGET_ARCH_arm64)
	write_reg(ctx, offsetof(struct pt_regs, regs[0]), 8, (__s64)value);
#endif
	return 0;
}
