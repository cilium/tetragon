// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_PRELOAD_H__
#define __UPROBE_PRELOAD_H__

#include "generic_maps.h"
#include "errmetrics.h"

struct preload_data {
	unsigned char data[4096];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, struct preload_data);
} sleepable_preload SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct preload_data);
} sleepable_preload_heap SEC(".maps");

#if defined(GENERIC_UPROBE) && defined(__TARGET_ARCH_x86)

FUNC_INLINE unsigned long
preload_string_arg(struct pt_regs *ctx)
{
	__u64 id = get_current_pid_tgid();
	return (unsigned long) map_lookup_elem(&sleepable_preload, &id);
}

FUNC_INLINE int
preload_string_type(struct pt_regs *ctx, struct event_config *config, unsigned long val)
{
	__u64 id = get_current_pid_tgid();
	struct preload_data *data;
	__u32 zero = 0;

	data = map_lookup_elem(&process_call_heap, &zero);
	if (!data)
		return 0;

	bpf_copy_from_user_str(data, sizeof(*data), (const void *)val, 0);
	map_update_elem(&sleepable_preload, &id, data, BPF_ANY);
	return 0;
}

FUNC_INLINE int
preload_pt_regs_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	struct config_reg_arg *reg;
	unsigned long val;
	__u8 shift;
	__s32 ty;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));

	reg = &config->reg_arg[index];
	shift = 64 - reg->size * 8;

	val = read_reg(ctx, reg->offset, shift);
	ty = config->arg[index];

	switch (ty) {
	case string_type:
		return preload_string_type(ctx, config, val);
	}

	return 0;
}

FUNC_INLINE int
uprobe_preload_x86(struct pt_regs *ctx)
{
	struct event_config *config;
	__u32 idx = get_index(ctx);

	config = map_lookup_elem(&config_map, &idx);
	if (!config)
		return 0;

	if (config->arm[0] & ARGM_PT_REGS_PRELOAD)
		preload_pt_regs_arg(ctx, config, 0);
	if (config->arm[1] & ARGM_PT_REGS_PRELOAD)
		preload_pt_regs_arg(ctx, config, 1);
	if (config->arm[2] & ARGM_PT_REGS_PRELOAD)
		preload_pt_regs_arg(ctx, config, 2);
	if (config->arm[3] & ARGM_PT_REGS_PRELOAD)
		preload_pt_regs_arg(ctx, config, 3);
	if (config->arm[4] & ARGM_PT_REGS_PRELOAD)
		preload_pt_regs_arg(ctx, config, 4);

	return 0;
}

#endif /* GENERIC_UPROBE && __TARGET_ARCH_x86 */

FUNC_INLINE int
uprobe_preload_cleanup(struct pt_regs *ctx)
{
	__u64 id = get_current_pid_tgid();

	map_delete_elem(&sleepable_preload, &id);
	return 0;
}

#endif /* __UPROBE_PRELOAD_H__ */
