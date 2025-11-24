// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __REGS_H__
#define __REGS_H__

#if defined(__TARGET_ARCH_x86)

FUNC_LOCAL __u64
read_reg(struct pt_regs *ctx, __u32 src, __u8 shift)
{
	/* Using inlined asm for same reason we use WRITE_REG above. */
#define READ_REG(reg) ({                                        \
	__u64 val;                                              \
	asm volatile("%[val] = *(u64 *)(%[ctx] + %[off])\n"     \
		     : [ctx] "+r"(ctx), [val] "+r"(val)         \
		     : [off] "i"(offsetof(struct pt_regs, reg)) \
		     :);                                        \
	val <<= shift;                                          \
	val >>= shift;                                          \
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

FUNC_LOCAL int
write_reg(struct pt_regs *ctx, __u32 dst, __u8 size, __u64 val)
{
	/*
	 * Using inlined asm to make sure we access context via 'ctx-reg + offset'.
	 * When using switch on all registers offset values, clang-18 uses * modified
	 * ctx-reg which fails verifier.
	 *
	 * Using clang-20 seems to work, but we need to upgrade first ;-)
	 */

#define WRITE_REG(reg) ({                                                  \
	asm volatile("if %[size] != 8 goto +2\n"                           \
		     "*(u64 *)(%[ctx] + %[off]) = %[val]\n"                \
		     "goto +8\n"                                           \
		     "if %[size] != 4 goto +2\n"                           \
		     "*(u32 *)(%[ctx] + %[off]) = %[val]\n"                \
		     "goto +5\n"                                           \
		     "if %[size] != 2 goto +2\n"                           \
		     "*(u16 *)(%[ctx] + %[off]) = %[val]\n"                \
		     "goto +2\n"                                           \
		     "if %[size] != 1 goto +1\n"                           \
		     "*(u8 *)(%[ctx] + %[off]) = %[val]\n"                 \
		     : [ctx] "+r"(ctx), [val] "+r"(val), [size] "+r"(size) \
		     : [off] "i"(offsetof(struct pt_regs, reg))            \
		     :);                                                   \
	0;                                                                 \
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

#endif /* __TARGET_ARCH_x86 */
#endif /* __REGS_H__*/
