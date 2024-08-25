// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _BPF_LSM_IMA__
#define _BPF_LSM_IMA__

#define MAX_IMA_HASH_SIZE 64

struct ima_hash {
	// Increase state each time hash value passed through bpf program call chain
	char state;
	char algo;
	char value[MAX_IMA_HASH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct ima_hash);
} ima_hash_map SEC(".maps");

#endif
