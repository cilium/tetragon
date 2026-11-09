// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __ENFORCER_H__
#define __ENFORCER_H__

#include "multi_kprobe.h"

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "errmetrics.h"

/* information to track how an enforcer notify action was triggered */
struct enforcer_act_info {
	__u32 func_id;
	__u32 arg;
} __attribute__((packed));

struct enforcer_data {
	__s16 error;
	__s16 signal;
	struct enforcer_act_info act_info;
} __attribute__((packed));

/* Match the separately created enforcer map's BTF-derived timer metadata
 * for Linux 6.1 map-in-map compatibility checks. The anonymous wrapper
 * forces complete BTF instead of a forward declaration in the inner map.
 */
#ifdef SHARED_KPROBE
#define ENFORCER_DATA_MAP_VALUE            \
	struct {                           \
		struct enforcer_data data; \
	}
#else
#define ENFORCER_DATA_MAP_VALUE struct enforcer_data
#endif

POLICY_MAP(enforcer_data,
	   __uint(type, BPF_MAP_TYPE_HASH);
	   __uint(max_entries, 1);
	   __type(key, __u64);
	   __type(value, ENFORCER_DATA_MAP_VALUE););

enum enforcer_missed_reason {
	ENFORCER_MISSED_OVERWRITTEN = 1,
	ENFORCER_MISSED_NOACTION = 2,
};

struct enforcer_missed_key {
	struct enforcer_act_info act_info;
	__u32 reason; // see enforcer_missed_reason for values
} __attribute__((packed));

/* map to keep track of missed notifications */
POLICY_MAP(enforcer_missed_notifications,
	   __uint(type, BPF_MAP_TYPE_HASH);
	   __uint(max_entries, 128);
	   POLICY_KEY(struct enforcer_missed_key);
	   POLICY_VALUE(__u32););

FUNC_INLINE void
enforcer_update_missed_notifications(struct enforcer_missed_key *key)
{
	int err;
	__u32 *counter = policy_lookup(&enforcer_missed_notifications, key), one = 1;

	if (counter) {
		lock_add(counter, one);
		return;
	}

	err = with_errmetrics_helper(policy_update, map_update_elem, &enforcer_missed_notifications, key, &one, BPF_NOEXIST);
	if (!err)
		return;

	/* in case we raced with another thread and an entry was already created, retry to do a
	 * lookup
	 */
	counter = policy_lookup(&enforcer_missed_notifications, key);
	if (counter) {
		lock_add(counter, one);
	}
}

FUNC_INLINE void do_enforcer_cleanup(void)
{
	struct enforcer_data *ptr;
	__u64 id = get_current_pid_tgid();

	ptr = policy_lookup(&enforcer_data, &id);
	if (ptr) {
		struct enforcer_missed_key missed_key = {
			.act_info = ptr->act_info,
			.reason = ENFORCER_MISSED_NOACTION,
		};
		enforcer_update_missed_notifications(&missed_key);
		policy_delete(&enforcer_data, &id);
	}
}

FUNC_INLINE void do_enforcer_action(int error, int signal, struct enforcer_act_info act_info)
{
	__u64 id = get_current_pid_tgid();
	struct enforcer_data *ptr, data = {
		.error = (__s16)error,
		.signal = (__s16)signal,
		.act_info = act_info,
	};

	ptr = policy_lookup(&enforcer_data, &id);
	if (ptr) {
		/* there is another entry already, update enforcer_missed_notifications */
		struct enforcer_missed_key missed_key = {
			.act_info = ptr->act_info,
			.reason = ENFORCER_MISSED_OVERWRITTEN,
		};
		enforcer_update_missed_notifications(&missed_key);
		*ptr = data;
	} else {
		with_errmetrics_helper(policy_update, map_update_elem, &enforcer_data, &id, &data, BPF_ANY);
	}
}

#endif /* __ENFORCER_H__ */
