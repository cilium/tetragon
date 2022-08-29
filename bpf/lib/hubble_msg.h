// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __HUBBLE_MSG_
#define __HUBBLE_MSG_

#include "msg_types.h"
#include "common.h"
#include "process.h"
#include "bpf_helpers.h"

struct msg_calltrace {
	__u64 stack[16];
	int32_t ret;
} __attribute__((packed));

struct event {
	int event;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, struct event);
} tcpmon_map SEC(".maps");

#endif // __HUBBLE_MSG_
