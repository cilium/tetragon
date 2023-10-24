// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __KILLER_H__
#define __KILLER_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

struct killer_data {
	__s16 error;
	__s16 signal;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct killer_data);
} killer_data SEC(".maps");

static inline __attribute__((always_inline)) void
do_killer_action(int error, int signal)
{
	__u64 id = get_current_pid_tgid();
	struct killer_data *ptr, data = {
		.error = (__s16)error,
		.signal = (__s16)signal,
	};

	ptr = map_lookup_elem(&killer_data, &id);
	if (ptr) {
		ptr->error = (__s16)error;
		ptr->signal = (__s16)signal;
	} else {
		map_update_elem(&killer_data, &id, &data, BPF_ANY);
	}
}

#endif /* __KILLER_H__ */
