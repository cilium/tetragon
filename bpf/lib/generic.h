// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _GENERIC__
#define _GENERIC__

#include "common.h"
#include "msg_types.h"
#include "process.h"

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
	bool pass;
	bool active[MAX_CONFIGURED_SELECTORS];
#ifdef __NS_CHANGES_FILTER
	__u64 match_ns;
#endif
#ifdef __CAP_CHANGES_FILTER
	__u64 match_cap;
#endif
};

/* value to mask an offsset into msg_generic_kprobe->args */
#define GENERIC_MSG_ARGS_MASK 0x7ff

struct msg_generic_kprobe {
	struct msg_common common;
	struct msg_execve_key current;
	struct msg_ns ns;
	struct msg_capabilities caps;
	__u64 func_id;
	__u64 retprobe_id;
	__u64 action;
	__u32 action_arg_id; // only one URL or FQDN action can be fired per match
	__u32 tid; // Thread ID that triggered the event
	__u64 kernel_stack_id; // Kernel stack trace ID on u32 and potential error, see flag in msg_common.flags
	__u64 user_stack_id; // User Stack trace ID
	/* anything above is shared with the userspace so it should match structs MsgGenericKprobe and MsgGenericTracepoint in Go */
	char args[24000];
	unsigned long a0, a1, a2, a3, a4;
	long argsoff[MAX_POSSIBLE_ARGS];
	struct msg_selector_data sel;
	__u32 idx; // attach cookie index
	__u32 tailcall_index_process; // recursion index for generic_process_event
	__u32 tailcall_index_selector; // recursion index for filter_read_arg
	int pass;
	union {
		struct {
			bool post; // true if event needs to be posted
		} lsm;
	};
};

FUNC_INLINE size_t generic_kprobe_common_size(void)
{
	return offsetof(struct msg_generic_kprobe, args);
}

#endif // _GENERIC__
