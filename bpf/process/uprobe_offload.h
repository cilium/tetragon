// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_OFFLOAD_H__
#define __UPROBE_OFFLOAD_H__

#include "regs.h"

struct reg_assignment {
	__u8 type;
	__u8 pad1;
	__u16 src;
	__u16 dst;
	__u8 src_size;
	__u8 dst_size;
	__u64 off;
};

#if defined(GENERIC_UPROBE)

#define REGS_MAX 18

#define ASM_ASSIGNMENT_TYPE_NONE      0
#define ASM_ASSIGNMENT_TYPE_CONST     1
#define ASM_ASSIGNMENT_TYPE_REG	      2
#define ASM_ASSIGNMENT_TYPE_REG_OFF   3
#define ASM_ASSIGNMENT_TYPE_REG_DEREF 4
#define ASM_ASSIGNMENT_TYPE_CEL	      5

struct uprobe_regs {
	struct reg_assignment ass[REGS_MAX];
	u32 cnt;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct uprobe_regs);
} regs_map SEC(".maps");

#define CEL_VALS_MAX  8
#define CEL_VALS_MASK (CEL_VALS_MAX - 1)

struct offload_data {
	__u32 idx;
	__u32 pad;
#ifdef __V61_BPF_PROG
	__u64 vals[CEL_VALS_MAX];
#endif
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, struct offload_data);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sleepable_offload SEC(".maps");

FUNC_INLINE void do_uprobe_override(void *ctx, struct offload_data *d)
{
	__u64 id = get_current_pid_tgid();
	struct offload_data *cur_data;

	/*
	 * This should not happen, it means that the override program was
	 * not executed for some reason.
	 */
	cur_data = with_errmetrics_ptr(map_lookup_elem, &sleepable_offload, &id);
	if (cur_data)
		*cur_data = *d;
	else
		with_errmetrics(map_update_elem, &sleepable_offload, &id, d, BPF_ANY);
}

FUNC_INLINE __u64
read_reg_ass(struct pt_regs *ctx, struct reg_assignment *ass)
{
	__u32 src = ass->src;
	__u8 shift = 64 - ass->src_size * 8;

	return read_reg(ctx, src, shift);
}

FUNC_INLINE int
uprobe_offload(struct pt_regs *ctx)
{
	__u64 val = 0, id = get_current_pid_tgid();
	struct reg_assignment *ass;
	struct uprobe_regs *regs;
	struct offload_data *d;
	__u32 i;
	int err;

	d = map_lookup_elem(&sleepable_offload, &id);
	if (!d)
		return 0;
	map_delete_elem(&sleepable_offload, &id);

	regs = map_lookup_elem(&regs_map, &d->idx);
	if (!regs)
		return 0;

	for (i = 0; i < REGS_MAX && i < regs->cnt; i++) {
		ass = &regs->ass[i];

		switch (ass->type) {
		case ASM_ASSIGNMENT_TYPE_CONST:
			write_reg(ctx, ass->dst, ass->dst_size, ass->off);
			break;
		case ASM_ASSIGNMENT_TYPE_REG:
			val = read_reg_ass(ctx, ass);
			write_reg(ctx, ass->dst, ass->dst_size, val);
			break;
		case ASM_ASSIGNMENT_TYPE_REG_OFF:
			val = read_reg_ass(ctx, ass);
			val += ass->off;
			write_reg(ctx, ass->dst, ass->dst_size, val);
			break;
		case ASM_ASSIGNMENT_TYPE_REG_DEREF:
			val = read_reg_ass(ctx, ass);
			err = probe_read_user(&val, sizeof(val), (void *)val + ass->off);
			if (!err)
				write_reg(ctx, ass->dst, ass->dst_size, val);
			break;
#ifdef __V61_BPF_PROG
		case ASM_ASSIGNMENT_TYPE_CEL:
			val = d->vals[ass->off & CEL_VALS_MASK];
			write_reg(ctx, ass->dst, ass->dst_size, val);
			break;
#endif /* __V61_BPF_PROG */
		case ASM_ASSIGNMENT_TYPE_NONE:
		default:
			break;
		}
	}
	return 0;
}
#endif /* GENERIC_UPROBE */
#endif /* __UPROBE_OFFLOAD_H__ */
