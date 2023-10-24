// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __LINUX_MODULE_H__
#define __LINUX_MODULE_H__

#ifndef TG_MODULE_NAME_LEN
#define TG_MODULE_NAME_LEN 64
#endif

struct tg_kernel_module {
	u32 sig_ok;
	u32 pad;
	u64 taints; /* same bits as kernel:taint_flags */
	char name[TG_MODULE_NAME_LEN];
} __attribute__((packed));

#endif
