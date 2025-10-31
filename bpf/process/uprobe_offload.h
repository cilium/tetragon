// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_OFFLOAD_H__
#define __UPROBE_OFFLOAD_H__

struct reg_assignment {
	__u8 type;
	__u8 pad1;
	__u16 src;
	__u16 dst;
	__u16 pad2;
	__u64 off;
};

#if defined(GENERIC_UPROBE) && defined(__TARGET_ARCH_x86)

#define REGS_MAX 18

#define ASM_ASSIGNMENT_TYPE_NONE      0
#define ASM_ASSIGNMENT_TYPE_CONST     1
#define ASM_ASSIGNMENT_TYPE_REG	      2
#define ASM_ASSIGNMENT_TYPE_REG_OFF   3
#define ASM_ASSIGNMENT_TYPE_REG_DEREF 4

struct uprobe_regs {
	struct reg_assignment ass[REGS_MAX];
	u32 cnt;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct uprobe_regs);
} regs_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, __u32);
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
		map_update_elem(&sleepable_offload, &id, &idx, BPF_ANY);
}

FUNC_INLINE int
write_reg(struct pt_regs *ctx, __u32 dst, __u64 val)
{
	/*
	 * Using inlined asm to make sure we access context via 'ctx-reg + offset'.
	 * When using switch on all registers offset values, clang-18 uses * modified
	 * ctx-reg which fails verifier.
	 *
	 * Using clang-20 seems to work, but we need to upgrade first ;-)
	 */
#define WRITE_REG(reg) ({                                       \
	asm volatile("*(u64 *)(%[ctx] + %[off]) = %[val]\n"     \
		     : [ctx] "+r"(ctx), [val] "+r"(val)         \
		     : [off] "i"(offsetof(struct pt_regs, reg)) \
		     :);                                        \
	0;                                                      \
})

	switch (dst) {
	case offsetof(struct pt_regs, r15):
		return WRITE_REG(r15);
	case offsetof(struct pt_regs, r14):
		return WRITE_REG(r14);
	case offsetof(struct pt_regs, r13):
		return WRITE_REG(r13);
	case offsetof(struct pt_regs, r12):
		return WRITE_REG(r12);
	case offsetof(struct pt_regs, bp):
		return WRITE_REG(bp);
	case offsetof(struct pt_regs, bx):
		return WRITE_REG(bx);
	case offsetof(struct pt_regs, r11):
		return WRITE_REG(r11);
	case offsetof(struct pt_regs, r10):
		return WRITE_REG(r10);
	case offsetof(struct pt_regs, r9):
		return WRITE_REG(r9);
	case offsetof(struct pt_regs, r8):
		return WRITE_REG(r8);
	case offsetof(struct pt_regs, ax):
		return WRITE_REG(ax);
	case offsetof(struct pt_regs, cx):
		return WRITE_REG(cx);
	case offsetof(struct pt_regs, dx):
		return WRITE_REG(dx);
	case offsetof(struct pt_regs, si):
		return WRITE_REG(si);
	case offsetof(struct pt_regs, di):
		return WRITE_REG(di);
	case offsetof(struct pt_regs, ip):
		return WRITE_REG(ip);
	case offsetof(struct pt_regs, sp):
		return WRITE_REG(sp);
	}

#undef WRITE_REG
	return 0;
}

FUNC_INLINE __u64
read_reg(struct pt_regs *ctx, __u32 src)
{
	/* Using inlined asm for same reason we use WRITE_REG above. */
#define READ_REG(reg) ({                                        \
	__u64 val;                                              \
	asm volatile("%[val] = *(u64 *)(%[ctx] + %[off])\n"     \
		     : [ctx] "+r"(ctx), [val] "+r"(val)         \
		     : [off] "i"(offsetof(struct pt_regs, reg)) \
		     :);                                        \
	val;                                                    \
})

	switch (src) {
	case offsetof(struct pt_regs, r15):
		return READ_REG(r15);
	case offsetof(struct pt_regs, r14):
		return READ_REG(r14);
	case offsetof(struct pt_regs, r13):
		return READ_REG(r13);
	case offsetof(struct pt_regs, r12):
		return READ_REG(r12);
	case offsetof(struct pt_regs, bp):
		return READ_REG(bp);
	case offsetof(struct pt_regs, bx):
		return READ_REG(bx);
	case offsetof(struct pt_regs, r11):
		return READ_REG(r11);
	case offsetof(struct pt_regs, r10):
		return READ_REG(r10);
	case offsetof(struct pt_regs, r9):
		return READ_REG(r9);
	case offsetof(struct pt_regs, r8):
		return READ_REG(r8);
	case offsetof(struct pt_regs, ax):
		return READ_REG(ax);
	case offsetof(struct pt_regs, cx):
		return READ_REG(cx);
	case offsetof(struct pt_regs, dx):
		return READ_REG(dx);
	case offsetof(struct pt_regs, si):
		return READ_REG(si);
	case offsetof(struct pt_regs, di):
		return READ_REG(di);
	case offsetof(struct pt_regs, ip):
		return READ_REG(ip);
	case offsetof(struct pt_regs, sp):
		return READ_REG(sp);
	}

#undef READ_REG
	return 0;
}

FUNC_INLINE int
uprobe_offload_x86(struct pt_regs *ctx)
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

	for (i = 0; i < REGS_MAX && i < regs->cnt; i++) {
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
	}
	return 0;
}
#endif /* GENERIC_UPROBE && __TARGET_ARCH_x86 */
#endif /* __UPROBE_OFFLOAD_H__ */
