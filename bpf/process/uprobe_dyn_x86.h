// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_X86_H__
#define __UPROBE_DYN_X86_H__

#if defined(__TARGET_ARCH_x86)

#if defined(GENERIC_UPROBE)

/*
X86:
`call` pushes the return address onto the stack (SP), and `ret` pops it
* need to manipulate user stack pointer via probe_write_user (see push_fake_frame() below)
*/

FUNC_INLINE void restore_orig_regs(struct pt_regs *ctx, struct pending_call *pc)
{
	ctx->di = pc->orig_regs[0];
	ctx->si = pc->orig_regs[1];
	ctx->dx = pc->orig_regs[2];
	ctx->cx = pc->orig_regs[3];
	ctx->r8 = pc->orig_regs[4];
	ctx->r9 = pc->orig_regs[5];
}

FUNC_INLINE void jump_to(struct pt_regs *ctx, __u64 addr)
{
	ctx->ip = addr;
}

FUNC_INLINE void push_fake_frame(struct pt_regs *ctx, struct pending_call *pc)
{
	ctx->sp -= 8;
	if (pc->stage != STAGE_FINAL_PENDING) {
		__u64 dummy = 0;
		probe_write_user((void *)ctx->sp, &dummy, sizeof(__u64));
	} else {
		probe_write_user((void *)ctx->sp, &pc->true_return_addr, sizeof(__u64));
	}
}

FUNC_INLINE void revert_ctx(struct pt_regs *ctx, struct pending_call *pc, __u64 pid_tgid)
{
	restore_orig_regs(ctx, pc);

	// Rebuild the call frame — required because at least one real `ret`
	// (mmap's, dlopen's, or dlsym's) has already consumed the original
	// return address from the stack by the time we get here.
	// pc->stage is set to STAGE_FINAL_PENDING to trigger correct behavior
	// in push_fake_frame(); see above.
	pc->stage = STAGE_FINAL_PENDING;
	push_fake_frame(ctx, pc);
	jump_to(ctx, pc->orig_addr);

	map_delete_elem(&pending_calls, &pid_tgid);

	// Signal that the flow is not working, and skip next time.
	skip_flow(pc->sym_id, pid_tgid);
}

FUNC_INLINE void store_orig_regs(struct pt_regs *ctx, struct pending_call *pc)
{
	pc->orig_regs[0] = ctx->di;
	pc->orig_regs[1] = ctx->si;
	pc->orig_regs[2] = ctx->dx;
	pc->orig_regs[3] = ctx->cx;
	pc->orig_regs[4] = ctx->r8;
	pc->orig_regs[5] = ctx->r9;
	pc->orig_addr = ctx->ip;
}

FUNC_INLINE void store_ret_addr(struct pt_regs *ctx, struct pending_call *pc)
{
	pc->true_return_addr = ctx->ip;
}

FUNC_INLINE void jump_to_mmap(struct pt_regs *ctx, __u64 mmap_addr)
{
	ctx->di = 0;
	ctx->si = 4096;
	ctx->dx = PROT_READ | PROT_WRITE;
	ctx->cx = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	ctx->r8 = -1;
	ctx->r9 = 0;
	jump_to(ctx, mmap_addr);
}

FUNC_INLINE void jump_to_dlopen(struct pt_regs *ctx, __u64 scratch, __u64 dlopen_addr)
{
	ctx->di = scratch;
	ctx->si = RTLD_NOW;
	jump_to(ctx, dlopen_addr);
}

FUNC_INLINE void jump_to_dlsym(struct pt_regs *ctx, __u64 handle, __u64 scratch, __u64 dlsym_addr)
{
	ctx->di = handle;
	ctx->si = scratch;
	jump_to(ctx, dlsym_addr);
}

#endif
#endif
#endif