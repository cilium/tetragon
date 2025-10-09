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
#include "regs.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

int generic_uprobe_setup_event(void *ctx);
int generic_uprobe_process_event(void *ctx);
int generic_uprobe_process_filter(void *ctx);
int generic_uprobe_filter_arg(void *ctx);
int generic_uprobe_actions(void *ctx);
int generic_uprobe_output(void *ctx);
int generic_uprobe_path(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__type(key, __u32);
	__array(values, int(void *));
} uprobe_calls SEC(".maps") = {
	.values = {
		[TAIL_CALL_SETUP] = (void *)&generic_uprobe_setup_event,
		[TAIL_CALL_PROCESS] = (void *)&generic_uprobe_process_event,
		[TAIL_CALL_FILTER] = (void *)&generic_uprobe_process_filter,
		[TAIL_CALL_ARGS] = (void *)&generic_uprobe_filter_arg,
		[TAIL_CALL_ACTIONS] = (void *)&generic_uprobe_actions,
		[TAIL_CALL_SEND] = (void *)&generic_uprobe_output,
#ifndef __V61_BPF_PROG
		[TAIL_CALL_PATH] = (void *)&generic_uprobe_path,
#endif
	},
};

#include "generic_maps.h"
#include "generic_calls.h"

#ifdef __MULTI_KPROBE
#define MAIN	"uprobe.multi/generic_uprobe"
#define COMMON	"uprobe.multi"
#define OFFLOAD "uprobe.multi.s/generic_uprobe"
#else
#define MAIN	"uprobe/generic_uprobe"
#define COMMON	"uprobe"
#define OFFLOAD "uprobe.s/generic_uprobe"
#endif

__attribute__((section((MAIN)), used)) int
generic_uprobe_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section(COMMON), used)) int
generic_uprobe_setup_event(void *ctx)
{
	return generic_process_event_and_setup(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section(COMMON), used)) int
generic_uprobe_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&uprobe_calls);
}

__attribute__((section(COMMON), used)) int
generic_uprobe_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter();
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &uprobe_calls, TAIL_CALL_SETUP);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section(COMMON), used)) int
generic_uprobe_filter_arg(void *ctx)
{
	return generic_filter_arg(ctx, (struct bpf_map_def *)&uprobe_calls, true);
}

__attribute__((section(COMMON), used)) int
generic_uprobe_actions(void *ctx)
{
	generic_actions(ctx, (struct bpf_map_def *)&uprobe_calls);
	return 0;
}

__attribute__((section(COMMON), used)) int
generic_uprobe_output(void *ctx)
{
	return generic_output(ctx, MSG_OP_GENERIC_UPROBE);
}

#ifndef __V61_BPF_PROG
__attribute__((section(COMMON), used)) int
generic_uprobe_path(void *ctx)
{
	return generic_path(ctx, (struct bpf_map_def *)&uprobe_calls);
}
#endif

FUNC_INLINE int
write_reg(struct pt_regs *ctx, __u32 dst, __u64 val)
{
	switch (dst) {
	case offsetof(struct pt_regs, r15): ctx->r15 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r14): ctx->r14 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r13): ctx->r13 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r12): ctx->r12 = (unsigned long) val; break;
	case offsetof(struct pt_regs, bp): ctx->bp = (unsigned long) val; break;
	case offsetof(struct pt_regs, bx): ctx->bx = (unsigned long) val; break;
	case offsetof(struct pt_regs, r11): ctx->r11 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r10): ctx->r10 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r9): ctx->r9 = (unsigned long) val; break;
	case offsetof(struct pt_regs, r8): ctx->r8 = (unsigned long) val; break;
	case offsetof(struct pt_regs, ax): ctx->ax = (unsigned long) val; break;
	case offsetof(struct pt_regs, cx): ctx->cx = (unsigned long) val; break;
	case offsetof(struct pt_regs, dx): ctx->dx = (unsigned long) val; break;
	case offsetof(struct pt_regs, si): ctx->si = (unsigned long) val; break;
	case offsetof(struct pt_regs, di): ctx->di = (unsigned long) val; break;
	case offsetof(struct pt_regs, ip): ctx->ip = (unsigned long) val; break;
	case offsetof(struct pt_regs, sp): ctx->sp = (unsigned long) val; break;
	}

	return 0;
}

FUNC_INLINE __u64
read_reg(struct pt_regs *ctx, __u32 src)
{
	switch (src) {
	case offsetof(struct pt_regs, r15): return ctx->r15;
	case offsetof(struct pt_regs, r14): return ctx->r14;
	case offsetof(struct pt_regs, r13): return ctx->r13;
	case offsetof(struct pt_regs, r12): return ctx->r12;
	case offsetof(struct pt_regs, bp): return ctx->bp;
	case offsetof(struct pt_regs, bx): return ctx->bx;
	case offsetof(struct pt_regs, r11): return ctx->r11;
	case offsetof(struct pt_regs, r10): return ctx->r10;
	case offsetof(struct pt_regs, r9): return ctx->r9;
	case offsetof(struct pt_regs, r8): return ctx->r8;
	case offsetof(struct pt_regs, ax): return ctx->ax;
	case offsetof(struct pt_regs, cx): return ctx->cx;
	case offsetof(struct pt_regs, dx): return ctx->dx;
	case offsetof(struct pt_regs, si): return ctx->si;
	case offsetof(struct pt_regs, di): return ctx->di;
	case offsetof(struct pt_regs, ip): return ctx->ip;
	case offsetof(struct pt_regs, sp): return ctx->sp;
	}

	return 0;
}
__attribute__((section(OFFLOAD), used)) int
generic_sleepable_offload(struct pt_regs *ctx)
{
	__u64 val, id = get_current_pid_tgid();
	struct reg_assignment *ass;
	struct uprobe_regs *regs;
	__u32 *idx, i;
	int err;

	idx = map_lookup_elem(&sleepable_offload, &id);
	if (!idx)
		return 0;
	map_delete_elem(&sleepable_offload, &id);

	regs = map_lookup_elem(&regs_map, idx);
	if (!regs)
		return 0;

	for (i = 0; i < REGS_MAX; i++) {
		ass = &regs->ass[i];

		switch (ass->type) {
		case ASM_ASSIGNMENT_TYPE_CONST:
			write_reg(ctx, ass->dst, ass->off);
			break;
		case ASM_ASSIGNMENT_TYPE_REG:
			val = read_reg(ctx, ass->src);
			write_reg(ctx, ass->dst, val);
			break;
		case ASM_ASSIGNMENT_TYPE_REG_OFF:
			val = read_reg(ctx, ass->src);
			val += ass->off;
			write_reg(ctx, ass->dst, val);
			break;
		case ASM_ASSIGNMENT_TYPE_REG_DEREF:
			val = read_reg(ctx, ass->src);
			err = probe_read_user(&val, sizeof(val), (void *)val + ass->off);
			if (!err)
				write_reg(ctx, ass->dst, val);
			break;
		case ASM_ASSIGNMENT_TYPE_NONE:
		default:
			break;
		}
		if (i == regs->cnt - 1)
			break;
	}
	return 0;
}
