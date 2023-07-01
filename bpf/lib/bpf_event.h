// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __BPF_EVENT_H
#define __BPF_EVENT_H

#include "bpf_helpers.h"

struct event {
	int event;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct event);
} tcpmon_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 255);
	__type(key, __u32);
	__type(value, __u64);
} lost_event SEC(".maps");

static inline __attribute__((always_inline)) void
inc_lost_event(void *ctx, __u8 op)
{
	__u64 *lost, val = 0;
	__u32 idx = op;

	lost = map_lookup_elem(&lost_event, &idx);
	if (!lost) {
		map_update_elem(&lost_event, &idx, &val, BPF_ANY);
		lost = map_lookup_elem(&lost_event, &idx);
	}

	if (lost)
		(*lost)++;
}

#define ENOSPC 28

static inline __attribute__((always_inline)) void
send_event(void *ctx, void *data, size_t total, __u8 op)
{
	long err;

	err = perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, total);
	if (err == -ENOSPC)
		inc_lost_event(ctx, op);
}

#endif // __BPF_EVENT_H
