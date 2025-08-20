// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_EVENT_H
#define __BPF_EVENT_H

#include "bpf_helpers.h"
#include "environ_conf.h"

struct event {
	int event;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct event);
} tcpmon_map SEC(".maps");

#ifdef __V511_BPF_PROG
// The ring buffer needs to have a size that is a multiple of a page size, and is a power of 2.
// Zero isn't acceptable, so we arbitrarily choose 4K as that is a common/default page size.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096); // This will be resized in user space.
} tg_rb_events SEC(".maps");

FUNC_INLINE long event_output(void *ctx, void *data, uint64_t size)
{
	struct tetragon_conf *conf;
	int zero = 0;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf && conf->use_perf_ring_buf)
		return perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
	return ringbuf_output(&tg_rb_events, data, size, 0);
}

#else
FUNC_INLINE long event_output(void *ctx, void *data, uint64_t size)
{
	return perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
}
#endif

#endif // __BPF_EVENT_H
