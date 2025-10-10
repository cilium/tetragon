// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef REGS_H__
#define REGS_H__

#define REGS_MAX 18

#define ASM_ASSIGNMENT_TYPE_NONE	0
#define ASM_ASSIGNMENT_TYPE_CONST	1
#define ASM_ASSIGNMENT_TYPE_REG		2
#define ASM_ASSIGNMENT_TYPE_REG_OFF	3
#define ASM_ASSIGNMENT_TYPE_REG_DEREF	4

struct reg_assignment {
	__u8 type;
	__u8 pad1;
	__u16 src;
	__u16 dst;
	__u16 pad2;
	__u64 off;
};

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
} write_offload SEC(".maps");

#endif /* REGS_H__ */
