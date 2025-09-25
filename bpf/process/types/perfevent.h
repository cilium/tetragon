// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __PERFEVENT_H__
#define __PERFEVENT_H__

#define KSYM_NAME_LEN 128U

struct perf_event_info_type {
	char kprobe_func[KSYM_NAME_LEN];
	__u64 config;
	__u64 probe_offset;
	__u32 type;
	__u32 pad;
};

#endif
