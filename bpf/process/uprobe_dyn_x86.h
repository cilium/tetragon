// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_X86_H__
#define __UPROBE_DYN_X86_H__

#if defined(__TARGET_ARCH_x86)

#if defined(GENERIC_UPROBE)

// X86:
// * `call` pushes the return address onto the stack (SP), and `ret` pops it
// * need to manipulate user stack pointer via probe_write_user (see push_fake_frame() below)

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

// Reserves 16 bytes, not 8, to preserve x86-64 SysV ABI 16-byte stack
// alignment at the callee's entry point. The real caller's `call`
// already left RSP at (16k + 8); an 8-byte push would land the callee
// at a 16-byte-aligned RSP, which VIOLATES the ABI requirement that
// sp % 16 == 8 immediately after a call. Simple functions (mmap)
// tolerate this; functions using SSE/AVX-aligned stack slots internally
// (dlopen's deeper glibc code) will SIGSEGV on a misaligned access.
// Only the low 8 bytes are used (the return address); the upper 8
// bytes are alignment padding.
FUNC_INLINE void push_fake_frame(struct pt_regs *ctx, struct pending_call *pc)
{
	__u64 reserve;

	// Ensure the callee is entered with sp % 16 == 8, regardless of
	// the current sp's starting parity (observed to differ between the
	// main thread and pthread-created threads on some glibc/kernel
	// combinations leading to sigsegv).
	// We always write the 8-byte return address at the new sp;
	// the remaining bytes (0 or 8) are pure alignment padding.
	reserve = (ctx->sp % 16 == 8) ? 16 : 8;
	ctx->sp -= reserve;
	probe_write_user((void *)ctx->sp, &pc->dispatch_addr, sizeof(__u64));
}

FUNC_INLINE void normalize_sp(struct pt_regs *ctx, struct pending_call *pc)
{
	// After the real callee's `ret` pops exactly 8 bytes, sp lands at
	// (push_point - reserve + 8). Depending on which reserve amount
	// was used, that's either expected_sp - 8 or expected_sp exactly.
	if (ctx->sp == pc->expected_sp - 8)
		ctx->sp += 8;
}

FUNC_INLINE void revert_ctx(struct pt_regs *ctx, struct pending_call *pc, __u64 pid_tgid, __u32 sym_id)
{
	restore_orig_regs(ctx, pc);
	jump_to(ctx, pc->orig_addr);
	// Signal that the flow is not working, and skip next time.
	skip_flow(pc, pid_tgid, sym_id);
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
	pc->expected_sp = ctx->sp;
	// Unused on x86
	pc->true_return_addr = ctx->ip;
}

FUNC_INLINE void store_ret_addr(struct pt_regs *ctx, struct pending_call *pc)
{
	pc->dispatch_addr = ctx->ip;
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

#endif /* GENERIC_UPROBE */
#endif /* __TARGET_ARCH_x86 */
#endif /* __UPROBE_DYN_X86_H__ */
