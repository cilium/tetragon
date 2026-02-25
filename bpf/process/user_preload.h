// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __USER_PRELOAD_H__
#define __USER_PRELOAD_H__

#include "generic_maps.h"
#include "generic_arg.h"
#include "errmetrics.h"
#include "usdt_arg.h"

struct preload_data {
	arg_status_t status;
	unsigned char data[4096];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, struct preload_data);
} sleepable_preload SEC(".maps");

#if defined(GENERIC_UPROBE) || defined(GENERIC_USDT)

FUNC_INLINE int
preload_string_type(struct pt_regs *ctx, struct event_config *config, unsigned long val,
		    arg_status_t status)
{
	__u64 id = get_current_pid_tgid();
	struct preload_data *data;
	__u32 zero = 0;
	void *init;

	init = map_lookup_elem(&heap_ro_zero, &zero);
	if (!init)
		return 0;

	map_update_elem(&sleepable_preload, &id, init, BPF_ANY);
	data = map_lookup_elem(&sleepable_preload, &id);
	if (!data)
		return 0;

	data->status = status;
	if (!status)
		bpf_copy_from_user_str(data->data, sizeof(data->data), (const void *)val, 0);
	return 0;
}

FUNC_INLINE int
preload_pt_regs_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	struct config_reg_arg *reg;
	unsigned long val;
	__u8 shift;
	__s32 ty;
	arg_status_t status = 0;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));

	reg = &config->reg_arg[index];
	shift = 64 - reg->size * 8;

	val = read_reg(ctx, reg->offset, shift);
	ty = config->arg[index];

	// NB: we currently don't support doing BTF style resolve for pointers
	// found in registers via pt_regs source. So the following extract_arg
	// call is not required, because config->btf_arg won't be populated
	// for the pt_regs case.
	extract_arg(config, index, &val, true, &status);

	switch (ty) {
	case string_type:
		return preload_string_type(ctx, config, val, status);
	}

	return 0;
}

FUNC_INLINE int
preload_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	unsigned long a;
	__s32 ty;
	arg_status_t status = 0;

#if defined(GENERIC_USDT)
	a = read_usdt_arg(ctx, config, index, true);
#else
	int arg_index = config->idx[index];

	switch (arg_index) {
	case 0:
		a = PT_REGS_PARM1_CORE(ctx);
		break;
	case 1:
		a = PT_REGS_PARM2_CORE(ctx);
		break;
	case 2:
		a = PT_REGS_PARM3_CORE(ctx);
		break;
	case 3:
		a = PT_REGS_PARM4_CORE(ctx);
		break;
	case 4:
		a = PT_REGS_PARM5_CORE(ctx);
		break;
	}
#endif

	extract_arg(config, index, &a, true, &status);

	ty = config->arg[index];

	probe_read(&a, sizeof(a), &a);

	switch (ty) {
	case string_type:
		return preload_string_type(ctx, config, a, status);
	}

	return 0;
}

struct preload_arg_data {
	struct event_config *config;
	struct pt_regs *ctx;
};

FUNC_LOCAL int
try_preload_arg(int idx, struct preload_arg_data *data)
{
	asm volatile("%[idx] &= %1 ;\n"
		     : [idx] "+r"(idx)
		     : "i"(MAX_POSSIBLE_ARGS));

	if (data->config->arm[idx] & ARGM_PRELOAD) {
		if (data->config->arm[idx] & ARGM_PT_REGS)
			preload_pt_regs_arg(data->ctx, data->config, idx);
		else
			preload_arg(data->ctx, data->config, idx);
	}
	return 0;
}

FUNC_INLINE int
user_preload(struct pt_regs *ctx)
{
	struct event_config *config;
	__u32 idx = get_index(ctx);
	int i;

	config = map_lookup_elem(&config_map, &idx);
	if (!config)
		return 0;

	struct preload_arg_data preload_data = {
		.config = config,
		.ctx = ctx,
	};
	if (CONFIG(ITER_NUM)) {
		bpf_for(i, 0, MAX_POSSIBLE_ARGS)
			try_preload_arg(i, &preload_data);
	} else {
#ifndef __V61_BPF_PROG
#pragma unroll
		for (i = 0; i < MAX_POSSIBLE_ARGS; ++i)
			try_preload_arg(i, &preload_data);
#else
		loop(MAX_POSSIBLE_ARGS, try_preload_arg, &preload_data, 0);
#endif /* __V61_BPF_PROG */
	}
	return 0;
}

#endif /* GENERIC_UPROBE || GENERIC_USDT*/

FUNC_INLINE int
user_preload_cleanup(struct pt_regs *ctx)
{
	__u64 id = get_current_pid_tgid();

	map_delete_elem(&sleepable_preload, &id);
	return 0;
}

#endif /* __USER_PRELOAD_H__ */
