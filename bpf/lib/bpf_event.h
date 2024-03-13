// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_EVENT_H
#define __BPF_EVENT_H

#include "bpf_helpers.h"

struct event {
	int event;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8LU * 1024LU * 1024LU); // 8MB
} tcpmon_map SEC(".maps");

#endif // __BPF_EVENT_H
