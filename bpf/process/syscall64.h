// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
#ifndef __SYSCALL_64_H__
#define __SYSCALL_64_H__

#define IS_32BIT 0x80000000

FUNC_INLINE __u64 syscall64_set_32bit(__u64 arg)
{
#if defined(__TARGET_ARCH_x86)
#define TS_COMPAT 0x0002
	struct thread_info *info;
	__u32 status;

	info = (struct thread_info *)get_current_task();
	probe_read(&status, sizeof(status), _(&info->status));
	if (status & TS_COMPAT)
		arg |= IS_32BIT;
	return arg;
#undef TS_COMPAT
#elif defined(__TARGET_ARCH_arm64)
#define TIF_32BIT 22
	struct thread_info *info;
	unsigned long flags;

	info = (struct thread_info *)get_current_task();
	probe_read(&flags, sizeof(flags), _(&info->flags));
	if (flags & (1 << TIF_32BIT))
		arg |= IS_32BIT;
	return arg;
#undef TIF_32BIT
#else
	/* unknown architecture, do nothing */
#endif
}

#endif /* __SYSCALL_64_H__ */
