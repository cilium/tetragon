// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_ARM64_H__
#define __UPROBE_DYN_ARM64_H__

#if defined(__TARGET_ARCH_arm64)

#if defined(GENERIC_UPROBE)

// ARM64:
// * `BL` stores return address directly in x30
// * `RET` simply branches to whatever is in x30
// * doesn't use stack for return addresses at all
// * return address is stored in a dedicated register (x30) (Link Register)
// * no need to manipulate user stack pointer (see x86 push_fake_frame())

FUNC_INLINE void restore_orig_regs(struct pt_regs *ctx, struct pending_call *pc)
{
	ctx->regs[0] = pc->orig_regs[0];
	ctx->regs[1] = pc->orig_regs[1];
	ctx->regs[2] = pc->orig_regs[2];
	ctx->regs[3] = pc->orig_regs[3];
	ctx->regs[4] = pc->orig_regs[4];
	ctx->regs[5] = pc->orig_regs[5];
	ctx->regs[6] = pc->orig_regs[6];
	ctx->regs[7] = pc->orig_regs[7];
}

FUNC_INLINE void jump_to(struct pt_regs *ctx, __u64 addr)
{
	ctx->pc = addr;
}

FUNC_INLINE void push_fake_frame(struct pt_regs *ctx, struct pending_call *pc)
{
	ctx->regs[30] = pc->true_return_addr;
}

FUNC_INLINE void revert_ctx(struct pt_regs *ctx, struct pending_call *pc, __u32 tgid, struct task_struct *task)
{
	restore_orig_regs(ctx, pc);

	push_fake_frame(ctx, pc);
	jump_to(ctx, pc->orig_addr);

	// Signal that the flow is not working, and skip next time.
	skip_flow(pc->sym_id, tgid, task);
}

FUNC_INLINE void store_orig_regs(struct pt_regs *ctx, struct pending_call *pc)
{
	pc->orig_regs[0] = ctx->regs[0];
	pc->orig_regs[1] = ctx->regs[1];
	pc->orig_regs[2] = ctx->regs[2];
	pc->orig_regs[3] = ctx->regs[3];
	pc->orig_regs[4] = ctx->regs[4];
	pc->orig_regs[5] = ctx->regs[5];
	pc->orig_regs[6] = ctx->regs[6];
	pc->orig_regs[7] = ctx->regs[7];
	pc->orig_addr = ctx->pc;
	pc->expected_sp = ctx->sp;
}

FUNC_INLINE void store_ret_addr(struct pt_regs *ctx, struct pending_call *pc)
{
	pc->true_return_addr = ctx->pc;
}

FUNC_INLINE void jump_to_mmap(struct pt_regs *ctx, __u64 mmap_addr)
{
	ctx->regs[0] = 0;
	ctx->regs[1] = 4096;
	ctx->regs[2] = PROT_READ | PROT_WRITE;
	ctx->regs[3] = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	ctx->regs[4] = -1;
	ctx->regs[5] = 0;
	jump_to(ctx, mmap_addr);
}

FUNC_INLINE void jump_to_dlopen(struct pt_regs *ctx, __u64 scratch, __u64 dlopen_addr)
{
	ctx->regs[0] = scratch;
	ctx->regs[1] = RTLD_NOW;
	jump_to(ctx, dlopen_addr);
}

#endif /* GENERIC_UPROBE */
#endif /* __TARGET_ARCH_arm64 */
#endif /* __UPROBE_DYN_ARM64_H__ */
