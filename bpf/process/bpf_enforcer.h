// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __ENFORCER_H__
#define __ENFORCER_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

struct enforcer_data {
	__s16 error;
	__s16 signal;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct enforcer_data);
} enforcer_data SEC(".maps");

FUNC_INLINE void do_enforcer_action(int error, int signal)
{
	__u64 id = get_current_pid_tgid();
	struct enforcer_data *ptr, data = {
		.error = (__s16)error,
		.signal = (__s16)signal,
	};

	ptr = map_lookup_elem(&enforcer_data, &id);
	if (ptr) {
		ptr->error = (__s16)error;
		ptr->signal = (__s16)signal;
	} else {
		map_update_elem(&enforcer_data, &id, &data, BPF_ANY);
	}
}

#endif /* __ENFORCER_H__ */
