// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef _GENERIC__
#define _GENERIC__

/* The namespace and capability changes filters require later kernels */
#ifdef __LARGE_BPF_PROG
#define __NS_CHANGES_FILTER
#define __CAP_CHANGES_FILTER
#endif

#define FILTER_SIZE 4096

#define MAX_POSSIBLE_ARGS	 5
#define MAX_POSSIBLE_SELECTORS	 31
#define SELECTORS_ACTIVE	 31
#define MAX_CONFIGURED_SELECTORS MAX_POSSIBLE_SELECTORS + 1

struct msg_selector_data {
	__u64 curr;
	__u64 pass;
	bool active[MAX_CONFIGURED_SELECTORS];
#ifdef __NS_CHANGES_FILTER
	__u64 match_ns;
#endif
#ifdef __CAP_CHANGES_FILTER
	__u64 match_cap;
#endif
};

struct msg_generic_kprobe {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_ns ns;
	struct msg_capabilities caps;
	__u64 id;
	__u64 thread_id;
	__u64 action;
	/* anything above is shared with the userspace so it should match structs MsgGenericKprobe and MsgGenericTracepoint in Go */
	char args[24000];
	unsigned long a0, a1, a2, a3, a4;
	long argsoff[MAX_POSSIBLE_ARGS];
	struct msg_selector_data sel;
	int idx;
	int func_id;
};

static inline __attribute__((always_inline)) size_t generic_kprobe_common_size()
{
	return offsetof(struct msg_generic_kprobe, args);
}

/* tracepoint args */
struct sched_execve_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int filename;
	int pid;
	int old_pid;
};

#ifndef ALIGNCHECKER
struct names_map_key {
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct names_map_key);
	__type(value, __u32);
} names_map SEC(".maps");

#endif // ALIGNCHECKER
#endif // _GENERIC__
