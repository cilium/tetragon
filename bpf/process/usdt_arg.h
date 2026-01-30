// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __USDT_ARG_H__
#define __USDT_ARG_H__

FUNC_INLINE unsigned long
read_usdt_arg(struct pt_regs *ctx, struct event_config *config, int index,
	      bool can_sleep)
{
	struct config_usdt_arg *arg;
	unsigned long val, off, idx;
	int err;

	index &= EVENT_CONFIG_MAX_USDT_ARG_MASK;
	arg = &config->usdt_arg[index];

	if (arg->type == USDT_ARG_TYPE_NONE)
		return 0;

	switch (arg->type) {
	case USDT_ARG_TYPE_CONST:
		/* Arg is just a constant ("-4@$-9" in USDT arg spec).
		 * value is recorded in arg->val_off directly.
		 */
		val = arg->val_off;
		break;
	case USDT_ARG_TYPE_REG:
		/* Arg is in a register (e.g, "8@%rax" in USDT arg spec),
		 * so we read the contents of that register directly from
		 * struct pt_regs. To keep things simple user-space parts
		 * record offsetof(struct pt_regs, <regname>) in arg->reg_off.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return 0;
		break;
	case USDT_ARG_TYPE_REG_DEREF:
		/* Arg is in memory addressed by register, plus some offset
		 * (e.g., "-4@-1204(%rbp)" in USDT arg spec). Register is
		 * identified like with BPF_USDT_ARG_REG case, and the offset
		 * is in arg->val_off. We first fetch register contents
		 * from pt_regs, then do another user-space probe read to
		 * fetch argument value itself.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return err;
		if (can_sleep)
			err = copy_from_user(&val, sizeof(val), (void *)val + arg->val_off);
		else
			err = probe_read_user(&val, sizeof(val), (void *)val + arg->val_off);
		if (err)
			return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		val >>= arg->shift;
#endif
		break;
	case USDT_ARG_TYPE_SIB:
		/* Arg is in memory addressed by SIB (Scale-Index-Base) mode
		 * (e.g., "-1@-96(%rbp,%rax,8)" in USDT arg spec). We first
		 * fetch the base register contents and the index register
		 * contents from pt_regs. Then we calculate the final address
		 * as base + (index * scale) + offset, and do a user-space
		 * probe read to fetch the argument value.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return err;
		off = arg->reg_idx_off & 0xfff;
		err = probe_read_kernel(&idx, sizeof(idx), (void *)ctx + off);
		if (err)
			return err;
		if (can_sleep)
			err = copy_from_user(&val, sizeof(val), (void *)(val + (idx << arg->scale) + arg->val_off));
		else
			err = probe_read_user(&val, sizeof(val), (void *)(val + (idx << arg->scale) + arg->val_off));
		if (err)
			return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		val >>= arg_spec->arg_bitshift;
#endif
		break;
	default:
		return 0;
	}

	/* cast arg from 1, 2, or 4 bytes to final 8 byte size clearing
	 * necessary upper arg_bitshift bits, with sign extension if argument
	 * is signed
	 */
	val <<= arg->shift;
	if (arg->sig)
		val = ((long)val) >> arg->shift;
	else
		val = val >> arg->shift;
	return val;
}

#endif /* __USDT_ARG_H__ */
