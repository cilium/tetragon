// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
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

#ifdef __V511_BPF_PROG
// The ring buffer needs to have a size that is a multiple of a page size, and is a power of 2.
// 65536 is valid across 4K, 16K, and 64K page sizes (ARM64). Resized in user space before use.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 65536); // Placeholder, resized by GetRBSize(). Must survive kernel ELF validation.
} tg_rb_events SEC(".maps");
#endif

#endif // __BPF_EVENT_H
