// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __LINUX_KPROBES_H__
#define __LINUX_KPROBES_H__

#ifndef KSYM_NAME_LEN
#define KSYM_NAME_LEN 128U
#endif

struct msg_kprobe {
	u64 addr;
	u32 offset;
	u32 pad;
	char symbol[KSYM_NAME_LEN];
} __attribute__((packed));

#endif
