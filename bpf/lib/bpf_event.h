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

static inline __attribute__((always_inline)) void
send_event(void *ctx, void *data, size_t total, __u8 op)
{
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, total);
}

#endif // __BPF_EVENT_H
