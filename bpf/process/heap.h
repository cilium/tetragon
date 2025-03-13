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
	__uint(value_size, STRING_MAPS_HEAP_SIZE);
} heap_ro_zero SEC(".maps");

#endif // __HEAP_H__
