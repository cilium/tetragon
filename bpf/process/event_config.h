// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __EVENT_CONFIG_H__
#define __EVENT_CONFIG_H__

#include "process/generic_maps.h"

// We do one tail-call per selector, we can have up to 5 selectors.
#define MAX_SELECTORS	   5
#define MAX_SELECTORS_MASK 7

struct config_btf_arg {
	__u32 offset;
	__u16 is_pointer;
	__u16 is_initialized;
} __attribute__((packed));

#define USDT_ARG_TYPE_NONE	0
#define USDT_ARG_TYPE_CONST	1
#define USDT_ARG_TYPE_REG	2
#define USDT_ARG_TYPE_REG_DEREF 3
#define USDT_ARG_TYPE_SIB	4

struct config_usdt_arg {
	__u64 val_off;
	__u32 reg_off;
	__u32 reg_idx_off;
	__u8 shift;
	__u8 type;
	__u8 sig;
	__u8 scale;
	__u32 pad1;
} __attribute__((packed));

struct config_reg_arg {
	__u16 offset;
	__u8 size;
	__u8 pad;
} __attribute__((packed));

struct extract_arg_data {
	struct config_btf_arg *btf_config;
	unsigned long *arg;
	bool can_sleep;
};

#define MAX_BTF_ARG_DEPTH	  10
#define EVENT_CONFIG_MAX_ARG	  5
#define EVENT_CONFIG_MAX_USDT_ARG 8
#define EVENT_CONFIG_MAX_REG_ARG  8

struct event_config {
	__u32 func_id;
	__s32 arg[EVENT_CONFIG_MAX_ARG];
	__u32 arm[EVENT_CONFIG_MAX_ARG];
	__u32 off[EVENT_CONFIG_MAX_ARG];
	__s32 idx[EVENT_CONFIG_MAX_ARG];
	__u32 syscall;
	__s32 argreturncopy;
	__s32 argreturn;
	/* arg return action specifies to act on the return value; currently
	 * supported actions include: TrackSock and UntrackSock.
	 */
	__u32 argreturnaction;
	/* policy id identifies the policy of this generic hook and is used to
	 * apply policies only on certain processes. A value of 0 indicates
	 * that the hook always applies and no check will be performed.
	 */
	__u32 policy_id;
	__u32 flags;
	__u32 pad;
	struct config_btf_arg btf_arg[EVENT_CONFIG_MAX_ARG][MAX_BTF_ARG_DEPTH];
	struct config_usdt_arg usdt_arg[EVENT_CONFIG_MAX_USDT_ARG];
	struct config_reg_arg reg_arg[EVENT_CONFIG_MAX_REG_ARG];
} __attribute__((packed));

FUNC_INLINE int arg_idx(int index)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return -1;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return -1;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	return config->idx[index];
}

#endif /* __EVENT_CONFIG_H__ */
