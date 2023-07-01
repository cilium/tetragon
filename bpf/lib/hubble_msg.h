// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __HUBBLE_MSG_
#define __HUBBLE_MSG_

#include "bpf_helpers.h"

struct event {
	int event;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct event);
} tcpmon_map SEC(".maps");

#endif // __HUBBLE_MSG_
