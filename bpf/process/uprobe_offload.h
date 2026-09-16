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

#define REGS_MAX   18
#define SOPATH_MAX 128
#define SONAME_MAX 32

#define ASM_ASSIGNMENT_TYPE_NONE      0
#define ASM_ASSIGNMENT_TYPE_CONST     1
#define ASM_ASSIGNMENT_TYPE_REG	      2
#define ASM_ASSIGNMENT_TYPE_REG_OFF   3
#define ASM_ASSIGNMENT_TYPE_REG_DEREF 4

struct uprobe_regs {
	struct reg_assignment ass[REGS_MAX];
	__u32 cnt;

	// Below is for dynamic override feature via SO loading; see "uprobe_dyn.h"
	char sopath[SOPATH_MAX]; // e.g. "/opt/safeguards/libsafemalloc.so"
	__u32 sopath_len;
	char soname[SONAME_MAX]; // e.g. "libsafemalloc.so"
	__u64 sym_addr; // symbol address without account for sopath base address
	__u64 mmap_addr; // mmap address without accounting for libc base address
	__u64 dlopen_addr; // mmap address without accounting for libc base address
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32); // sym_id, based upon UprobeID and selector idx (see UprobeRegsMapID())
	__type(value, struct uprobe_regs);
} regs_map SEC(".maps");

// uprobe_dyn uses `regs_map`; import it after the map has been declared.
#ifdef __V511_BPF_PROG

// While this code only runs for 6.18+,
// it uses BPF_MAP_TYPE_TASK_STORAGE for pending_calls map
// that requires 5.11+. The code gets compiled and verified
// even if we won't run it.
#include "uprobe_dyn.h"

#else /* __V511_BPF_PROG */

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, struct uprobe_regs *regs, __u32 sym_id)
{
	return 0;
}

#endif /* __V511_BPF_PROG */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sleepable_offload SEC(".maps");

FUNC_INLINE void do_uprobe_override(void *ctx, __u32 idx)
{
	__u64 id = get_current_pid_tgid();
	__u32 *idxp;

	/*
	 * This should not happen, it means that the override program was
	 * not executed for some reason.
	 */
	idxp = with_errmetrics_ptr(map_lookup_elem, &sleepable_offload, &id);
	if (idxp)
		*idxp = idx;
	else
		with_errmetrics(map_update_elem, &sleepable_offload, &id, &idx, BPF_ANY);
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
	__u32 *idx, i;
	int err;

	idx = map_lookup_elem(&sleepable_offload, &id);
	if (!idx)
		return 0;
	map_delete_elem(&sleepable_offload, &id);

	regs = map_lookup_elem(&regs_map, idx);
	if (!regs)
		return 0;

	// We expect to fully override the call to
	// a dynamically loaded one
	if (regs->sopath_len > 0) {
		return uprobe_dyn_state_machine(ctx, regs, *idx);
	}

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
		case ASM_ASSIGNMENT_TYPE_NONE:
		default:
			break;
		}
	}
	return 0;
}
#endif /* GENERIC_UPROBE */
#endif /* __UPROBE_OFFLOAD_H__ */
