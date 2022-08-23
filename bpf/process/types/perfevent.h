// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __PERFEVENT_H__
#define __PERFEVENT_H__

struct perf_event_info_type {
	char kprobe_func[128U];
	__u32 type;
	__u64 config;
	__u64 probe_offset;
};

#endif
