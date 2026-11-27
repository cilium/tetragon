// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef BPF_POLICYCONF_H__
#define BPF_POLICYCONF_H__

#include "multi_kprobe.h"

// NB: values should match the ones defined in go (EnforceMode, MonitorMode)
enum {
	POLICY_MODE_ENFORCE = 0,
	POLICY_MODE_MONITOR = 1,
	POLICY_MODE_MONITOR_ONLY = 2,
};

struct policy_conf {
	__u8 mode;
} __attribute__((packed));

POLICY_MAP(policy_conf,
	   __uint(type, BPF_MAP_TYPE_ARRAY);
	   __uint(map_flags, POLICY_ARRAY_FLAGS);
	   __uint(max_entries, 1);
	   POLICY_KEY(__u32);
	   POLICY_VALUE(struct policy_conf););

#endif /* BPF_POLICYCONF_H__ */
