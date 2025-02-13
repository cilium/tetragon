// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef BPF_POLICYCONF_H__
#define BPF_POLICYCONF_H__

// NB: values should match the ones defined in go (EnforceMode, MonitorMode)
enum {
	POLICY_MODE_ENFORCE = 0,
	POLICY_MODE_MONITOR = 1,
};

struct policy_conf {
	__u8 mode;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_conf);
} policy_conf SEC(".maps");

#endif /* BPF_POLICYCONF_H__ */
