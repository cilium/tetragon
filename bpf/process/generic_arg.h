// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_ARG_H__
#define __GENERIC_ARG_H__

FUNC_INLINE int
extract_arg_depth(u32 i, struct extract_arg_data *data)
{
	if (i >= MAX_BTF_ARG_DEPTH || !data->btf_config[i].is_initialized)
		return 1;
	*data->arg = *data->arg + data->btf_config[i].offset;
	if (data->btf_config[i].is_pointer) {
		if (data->can_sleep)
			copy_from_user((void *)data->arg, sizeof(char *), (void *)*data->arg);
		else
			probe_read((void *)data->arg, sizeof(char *), (void *)*data->arg);
	}
	return 0;
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE void extract_arg(struct event_config *config, int index, unsigned long *a,
			     bool can_sleep)
{
	struct config_btf_arg *btf_config;

	if (index >= EVENT_CONFIG_MAX_ARG)
		return;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	btf_config = config->btf_arg[index];
	if (btf_config->is_initialized) {
		struct extract_arg_data extract_data = {
			.btf_config = btf_config,
			.arg = a,
			.can_sleep = can_sleep,
		};
		int i;

		if (CONFIG(ITER_NUM)) {
			bpf_for(i, 0, MAX_BTF_ARG_DEPTH)
			{
				if (extract_arg_depth(i, &extract_data))
					break;
			}
		} else {
#ifndef __V61_BPF_PROG
#pragma unroll
			for (i = 0; i < MAX_BTF_ARG_DEPTH; ++i) {
				if (extract_arg_depth(i, &extract_data))
					break;
			}
#else
			loop(MAX_BTF_ARG_DEPTH, extract_arg_depth, &extract_data, 0);
#endif /* __V61_BPF_PROG */
		}
	}
}
#else
FUNC_INLINE void extract_arg(struct event_config *config, int index, unsigned long *a,
			     bool can_sleep)
{
}
#endif /* __LARGE_BPF_PROG */

#endif /* __GENERIC_ARG_H__ */
