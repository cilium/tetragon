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

struct bpf_map_def __attribute__((section("maps"), used)) tcpmon_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct event),
};
#endif // __HUBBLE_MSG_
