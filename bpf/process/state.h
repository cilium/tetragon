// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __STATE_H__
#define __STATE_H__

#include "vmlinux.h"
#include "compiler.h"
#include "bpf_helpers.h"
#include "errmetrics.h"

// Mirrored by StateScope* and StateOp* in pkg/selectors/kernel.go.
enum {
	STATE_SCOPE_SYSTEM = 0,
	STATE_SCOPE_PROCESS = 1,
	STATE_SCOPE_THREAD = 2,
};

enum {
	STATE_OP_SET = 0,
	STATE_OP_DELETE = 1,
};

struct state_key {
	__u32 id;
	__u32 pid;
	__u64 start_time;
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

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, struct state_key);
	__type(value, struct state_value);
} tg_scoped_state_map SEC(".maps");

FUNC_INLINE int state_scoped_get_key(__u32 id, __u32 scope, struct state_key *key)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u64 pid_tgid = get_current_pid_tgid();

	key->id = id;
	key->start_time = 0;
	switch (scope) {
	case STATE_SCOPE_PROCESS:
		key->pid = pid_tgid >> 32;
		if (probe_read_kernel(&task, sizeof(task), _(&task->group_leader)))
			return -EFAULT;
		break;
	case STATE_SCOPE_THREAD:
		key->pid = (__u32)pid_tgid;
		break;
	default:
		return -EINVAL;
	}

	/* Pair the ID with task start_time so recycled threads and processes
	 * cannot reuse state.
	 */
	return probe_read_kernel(&key->start_time, sizeof(key->start_time),
				 _(&task->start_time));
}

FUNC_INLINE struct state_value *state_lookup(__u32 id, __u32 scope)
{
	struct state_key key;
	int err;

	if (scope == STATE_SCOPE_SYSTEM)
		return map_lookup_elem(&tg_state_map, &id);

	err = state_scoped_get_key(id, scope, &key);
	if (err) {
		errmetrics(-err);
		return 0;
	}
	return map_lookup_elem(&tg_scoped_state_map, &key);
}

FUNC_INLINE int state_update(__u32 id, __u32 scope, __u32 op, __u64 data)
{
	struct state_value value = { .data = data };
	struct state_key key;
	const void *map_key;
	void *map;
	int err;

	switch (scope) {
	case STATE_SCOPE_SYSTEM:
		map = &tg_state_map;
		map_key = &id;
		break;
	case STATE_SCOPE_PROCESS:
	case STATE_SCOPE_THREAD:
		err = state_scoped_get_key(id, scope, &key);
		if (err)
			return err;
		map = &tg_scoped_state_map;
		map_key = &key;
		break;
	default:
		return -EINVAL;
	}

	switch (op) {
	case STATE_OP_DELETE:
		err = map_delete_elem(map, map_key);
		return err == -ENOENT ? 0 : err;
	case STATE_OP_SET:
		return map_update_elem(map, map_key, &value, BPF_ANY);
	default:
		return -EINVAL;
	}
}

#endif /* __STATE_H__ */
