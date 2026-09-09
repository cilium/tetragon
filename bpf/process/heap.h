// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __HEAP_H__
#define __HEAP_H__

#define HEAP_RO_SIZE 16384

struct heap_ro_value {
	/*
	 * STRING_MAPS_HEAP_SIZE
	 * sizeof(struct ratelimit_key) + 128
	 */
	char buf[HEAP_RO_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_ro_value);
} heap_ro_zero SEC(".maps");

struct heap_value {
	union {
		char fdinstall[4104]; /* 4096B paths + 4B length + 4B flags */
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_value);
} heap SEC(".maps");

#endif // __HEAP_H__
