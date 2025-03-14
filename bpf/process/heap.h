// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __HEAP_H__
#define __HEAP_H__

#include "ratelimit_maps.h"

struct heap_ro_value {
	union {
		char string_maps_heap[STRING_MAPS_HEAP_SIZE];
		char ratelimit_heap[sizeof(struct ratelimit_key) + 128];
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_ro_value);
} heap_ro_zero SEC(".maps");

struct heap_value {
	union {
		char fdinstall[264];
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_value);
} heap SEC(".maps");

#endif // __HEAP_H__
