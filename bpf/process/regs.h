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

#if defined(__TARGET_ARCH_arm64)

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
	case offsetof(struct pt_regs, sp):
		return READ_REG(sp);
	case offsetof(struct pt_regs, pc):
		return READ_REG(pc);
#undef READ_REG
#define READ_REG(offset) ({                                                     \
	__u64 val;                                                              \
	asm volatile("%[val] = *(u64 *)(%[ctx] + %[off])\n"                     \
		     : [ctx] "+r"(ctx), [val] "+r"(val)                         \
		     : [off] "i"(offsetof(struct pt_regs, regs) + 8 * (offset)) \
		     :);                                                        \
	val <<= shift;                                                          \
	val >>= shift;                                                          \
	val;                                                                    \
})
	case offsetof(struct pt_regs, regs) + 8 * 0:
		return READ_REG(0);
	case offsetof(struct pt_regs, regs) + 8 * 1:
		return READ_REG(1);
	case offsetof(struct pt_regs, regs) + 8 * 2:
		return READ_REG(2);
	case offsetof(struct pt_regs, regs) + 8 * 3:
		return READ_REG(3);
	case offsetof(struct pt_regs, regs) + 8 * 4:
		return READ_REG(4);
	case offsetof(struct pt_regs, regs) + 8 * 5:
		return READ_REG(5);
	case offsetof(struct pt_regs, regs) + 8 * 6:
		return READ_REG(6);
	case offsetof(struct pt_regs, regs) + 8 * 7:
		return READ_REG(7);
	case offsetof(struct pt_regs, regs) + 8 * 8:
		return READ_REG(8);
	case offsetof(struct pt_regs, regs) + 8 * 9:
		return READ_REG(9);
	case offsetof(struct pt_regs, regs) + 8 * 10:
		return READ_REG(10);
	case offsetof(struct pt_regs, regs) + 8 * 11:
		return READ_REG(11);
	case offsetof(struct pt_regs, regs) + 8 * 12:
		return READ_REG(12);
	case offsetof(struct pt_regs, regs) + 8 * 13:
		return READ_REG(13);
	case offsetof(struct pt_regs, regs) + 8 * 14:
		return READ_REG(14);
	case offsetof(struct pt_regs, regs) + 8 * 15:
		return READ_REG(15);
	case offsetof(struct pt_regs, regs) + 8 * 16:
		return READ_REG(16);
	case offsetof(struct pt_regs, regs) + 8 * 17:
		return READ_REG(17);
	case offsetof(struct pt_regs, regs) + 8 * 18:
		return READ_REG(18);
	case offsetof(struct pt_regs, regs) + 8 * 19:
		return READ_REG(19);
	case offsetof(struct pt_regs, regs) + 8 * 20:
		return READ_REG(20);
	case offsetof(struct pt_regs, regs) + 8 * 21:
		return READ_REG(21);
	case offsetof(struct pt_regs, regs) + 8 * 22:
		return READ_REG(22);
	case offsetof(struct pt_regs, regs) + 8 * 23:
		return READ_REG(23);
	case offsetof(struct pt_regs, regs) + 8 * 24:
		return READ_REG(24);
	case offsetof(struct pt_regs, regs) + 8 * 25:
		return READ_REG(25);
	case offsetof(struct pt_regs, regs) + 8 * 26:
		return READ_REG(26);
	case offsetof(struct pt_regs, regs) + 8 * 27:
		return READ_REG(27);
	case offsetof(struct pt_regs, regs) + 8 * 28:
		return READ_REG(28);
	case offsetof(struct pt_regs, regs) + 8 * 29:
		return READ_REG(29);
	case offsetof(struct pt_regs, regs) + 8 * 30:
		return READ_REG(30);
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
		     "goto +2\n"                                           \
		     "if %[size] != 4 goto +1\n"                           \
		     "*(u32 *)(%[ctx] + %[off]) = %[val]\n"                \
		     : [ctx] "+r"(ctx), [val] "+r"(val), [size] "+r"(size) \
		     : [off] "i"(offsetof(struct pt_regs, reg))            \
		     :);                                                   \
	0;                                                                 \
})

	switch (dst) {
	case offsetof(struct pt_regs, sp):
		return WRITE_REG(sp);
	case offsetof(struct pt_regs, pc):
		return WRITE_REG(pc);
#undef WRITE_REG
#define WRITE_REG(offset) ({                                                    \
	asm volatile("if %[size] != 8 goto +2\n"                                \
		     "*(u64 *)(%[ctx] + %[off]) = %[val]\n"                     \
		     "goto +2\n"                                                \
		     "if %[size] != 4 goto +1\n"                                \
		     "*(u32 *)(%[ctx] + %[off]) = %[val]\n"                     \
		     : [ctx] "+r"(ctx), [val] "+r"(val), [size] "+r"(size)      \
		     : [off] "i"(offsetof(struct pt_regs, regs) + 8 * (offset)) \
		     :);                                                        \
	0;                                                                      \
})
	case offsetof(struct pt_regs, regs) + 8 * 0:
		WRITE_REG(0);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 1:
		WRITE_REG(1);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 2:
		WRITE_REG(2);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 3:
		WRITE_REG(3);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 4:
		WRITE_REG(4);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 5:
		WRITE_REG(5);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 6:
		WRITE_REG(6);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 7:
		WRITE_REG(7);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 8:
		WRITE_REG(8);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 9:
		WRITE_REG(9);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 10:
		WRITE_REG(10);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 11:
		WRITE_REG(11);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 12:
		WRITE_REG(12);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 13:
		WRITE_REG(13);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 14:
		WRITE_REG(14);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 15:
		WRITE_REG(15);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 16:
		WRITE_REG(16);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 17:
		WRITE_REG(17);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 18:
		WRITE_REG(18);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 19:
		WRITE_REG(19);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 20:
		WRITE_REG(20);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 21:
		WRITE_REG(21);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 22:
		WRITE_REG(22);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 23:
		WRITE_REG(23);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 24:
		WRITE_REG(24);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 25:
		WRITE_REG(25);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 26:
		WRITE_REG(26);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 27:
		WRITE_REG(27);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 28:
		WRITE_REG(28);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 29:
		WRITE_REG(29);
		break;
	case offsetof(struct pt_regs, regs) + 8 * 30:
		WRITE_REG(30);
		break;
	}

#undef WRITE_REG

	return 0;
}

#endif /* __TARGET_ARCH_arm64 */

#endif /* __REGS_H__*/
