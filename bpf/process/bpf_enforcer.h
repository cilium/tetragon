// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __ENFORCER_H__
#define __ENFORCER_H__

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "errmetrics.h"

/* information to track how an enforcer notify action was triggered */
struct enforcer_act_info {
	__u32 func_id;
	__u32 arg;
} __attribute__((packed));

struct enforcer_data {
	__u64 start_time; /* of the task that wrote the record, guards against pid_tgid reuse */
	__s16 error;
	__s16 signal;
	struct enforcer_act_info act_info;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct enforcer_data);
} enforcer_data SEC(".maps");

enum enforcer_missed_reason {
	ENFORCER_MISSED_OVERWRITTEN = 1,
	ENFORCER_MISSED_NOACTION = 2,
	ENFORCER_MISSED_STALE = 3,
};

struct enforcer_missed_key {
	struct enforcer_act_info act_info;
	__u32 reason; // see enforcer_missed_reason for values
} __attribute__((packed));

/* map to keep track of missed notifications */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct enforcer_missed_key);
	__type(value, __u32);
} enforcer_missed_notifications SEC(".maps");

FUNC_INLINE void
enforcer_update_missed_notifications(struct enforcer_act_info act_info, __u32 reason)
{
	struct enforcer_missed_key key = {
		.act_info = act_info,
		.reason = reason,
	};
	int err;
	__u32 *counter = map_lookup_elem(&enforcer_missed_notifications, &key), one = 1;

	if (counter) {
		lock_add(counter, one);
		return;
	}

	err = with_errmetrics(map_update_elem, &enforcer_missed_notifications, &key, &one, BPF_NOEXIST);
	if (!err)
		return;

	/* in case we raced with another thread and an entry was already created, retry to do a
	 * lookup
	 */
	counter = map_lookup_elem(&enforcer_missed_notifications, &key);
	if (counter) {
		lock_add(counter, one);
	}
}

FUNC_INLINE void do_enforcer_cleanup(void)
{
	struct enforcer_data *ptr;
	__u64 id = get_current_pid_tgid();

	ptr = map_lookup_elem(&enforcer_data, &id);
	if (ptr) {
		enforcer_update_missed_notifications(ptr->act_info, ENFORCER_MISSED_NOACTION);
		map_delete_elem(&enforcer_data, &id);
	}
}

FUNC_INLINE __u64 enforcer_task_start_time(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u64 start_time = 0;

	probe_read_kernel(&start_time, sizeof(start_time), _(&task->start_time));
	return start_time;
}

FUNC_INLINE void do_enforcer_action(int error, int signal, struct enforcer_act_info act_info)
{
	__u64 id = get_current_pid_tgid();
	struct enforcer_data *ptr, data = {
		.start_time = enforcer_task_start_time(),
		.error = (__s16)error,
		.signal = (__s16)signal,
		.act_info = act_info,
	};

	ptr = map_lookup_elem(&enforcer_data, &id);
	if (ptr) {
		/* there is another entry already, update enforcer_missed_notifications */
		enforcer_update_missed_notifications(ptr->act_info, ENFORCER_MISSED_OVERWRITTEN);
		*ptr = data;
	} else {
		with_errmetrics(map_update_elem, &enforcer_data, &id, &data, BPF_ANY);
	}
}

#endif /* __ENFORCER_H__ */
