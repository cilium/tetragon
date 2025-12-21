// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

/* The namespace and capability changes filters require later kernels */
#ifdef __LARGE_BPF_PROG
#define __NS_CHANGES_FILTER
#define __CAP_CHANGES_FILTER
#endif

struct heap_exe {
	char buf[BINARY_PATH_MAX_LEN];
	char end[STRING_POSTFIX_MAX_LENGTH];
	__u32 len;
	__u32 error;
	__u32 arg_len;
	__u32 arg_start;
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_event {
	struct msg_common common;
	struct msg_k8s kube;
	struct msg_execve_key parent;
	__u64 parent_flags;
	struct msg_cred creds;
	struct msg_ns ns;
	struct msg_execve_key cleanup_key;
	/* if add anything above please also update the args of
	 * validate_msg_execve_size() in bpf_execve_event.c */
	union {
		struct msg_process process;
		char buffer[PADDED_BUFFER];
	};
	/* below fields are not part of the event, serve just as
	 * heap for execve programs
	 */
#ifdef __LARGE_BPF_PROG
	struct heap_exe exe;
#endif
}; // All fields aligned so no 'packed' attribute.

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

struct generic_path {
	int state;
	int off;
	int cnt;
	struct path path_buf;
	const struct path *path;
	struct dentry *root_dentry;
	struct vfsmount *root_mnt;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
};

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
	struct execve_map_value curr;
	struct heap_exe exe;
#ifndef __V61_BPF_PROG
	struct generic_path path;
#endif
};

FUNC_INLINE int64_t validate_msg_execve_size(int64_t size)
{
	size_t max = sizeof(struct msg_execve_event);

	/* validate_msg_size() calls need to happen near caller using the
	 * size. Otherwise, depending on kernel version, the verifier may
	 * lose track of the size bounds. Place a compiler barrier here
	 * otherwise clang will likely place this check near other msg
	 * population calls which can be significant distance away resulting
	 * in losing bounds on older kernels where bounds are not tracked
	 * as rigorously.
	 */
	compiler_barrier();
	if (size > max)
		size = max;
	if (size < 1)
		size = offsetof(struct msg_execve_event, buffer);
	compiler_barrier();
	return size;
}

FUNC_INLINE size_t generic_kprobe_common_size(void)
{
	return offsetof(struct msg_generic_kprobe, args);
}
