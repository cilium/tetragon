// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __STATE_H__
#define __STATE_H__

#include "vmlinux.h"
#include "compiler.h"
#include "bpf_helpers.h"
#include "errno.h"

// Mirrored by StateOp* in pkg/selectors/kernel.go
enum {
	STATE_OP_SET = 0,
	STATE_OP_DELETE = 1,
};

struct state_value {
	__u64 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u32);
	__type(value, struct state_value);
} tg_state_map SEC(".maps");

FUNC_INLINE struct state_value *state_lookup(__u32 id)
{
	return map_lookup_elem(&tg_state_map, &id);
}

FUNC_INLINE int state_update(__u32 state_key, __u32 op, __u64 state_data)
{
	struct state_value new_state_value;
	int map_ret;
	int err = 0;

	switch (op) {
	case STATE_OP_DELETE: {
		map_ret = map_delete_elem(&tg_state_map, &state_key);
		if (map_ret != 0 && map_ret != -ENOENT)
			err = -1;
		break;
	}
	case STATE_OP_SET: {
		new_state_value.data = state_data;
		if (map_update_elem(&tg_state_map, &state_key, &new_state_value, BPF_ANY))
			err = -1;
		break;
	}
	default:
		err = -1;
		break;
	}
	return err;
}

#endif /* __STATE_H__ */
