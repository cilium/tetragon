// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RETPROBE_MAP_H__
#define __RETPROBE_MAP_H__

#include "bpf_tracing.h"
#include "bpf_errmetrics.h"

struct retprobe_key {
	u64 id;
	u64 tid;
};

struct retprobe_info {
	unsigned long ktime_enter;
	unsigned long ptr;
	unsigned long cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct retprobe_key);
	__type(value, struct retprobe_info);
} retprobe_map SEC(".maps");

FUNC_INLINE bool
retprobe_map_get(__u64 id, __u64 tid, struct retprobe_info *bufp)
{
	struct retprobe_info *info;
	struct retprobe_key key = {
		.id = id,
		.tid = tid,
	};

	info = map_lookup_elem(&retprobe_map, &key);
	if (!info)
		return false;
	if (bufp)
		*bufp = *info;
	map_delete_elem(&retprobe_map, &key);
	return true;
}

FUNC_INLINE void retprobe_map_clear(__u64 id, __u64 tid)
{
	struct retprobe_key key = {
		.id = id,
		.tid = tid,
	};
	struct retprobe_info *info = map_lookup_elem(&retprobe_map, &key);

	if (info)
		map_delete_elem(&retprobe_map, &key);
}

FUNC_INLINE void
retprobe_map_set(__u64 id, __u64 tid, __u64 ktime, unsigned long ptr)
{
	struct retprobe_info info = {
		.ktime_enter = ktime,
		.ptr = ptr,
	};
	struct retprobe_key key = {
		.id = id,
		.tid = tid,
	};

	with_errmetrics(map_update_elem, &retprobe_map, &key, &info, BPF_ANY);
}

FUNC_INLINE void
retprobe_map_set_iovec(__u64 id, __u64 tid, __u64 ktime, unsigned long ptr,
		       unsigned long cnt)
{
	struct retprobe_info info = {
		.ktime_enter = ktime,
		.ptr = ptr,
		.cnt = cnt,
	};
	struct retprobe_key key = {
		.id = id,
		.tid = tid,
	};

	with_errmetrics(map_update_elem, &retprobe_map, &key, &info, BPF_ANY);
}

/**
 * Some FGS generic kprobes include an (entry) kprobe as well as a retprobe,
 * where we need a way to match data collected at the kprobe (at function entry)
 * with the corressponding retprobe (at function return). The typical example of
 * this is a read system call, where we want to copy the data read. The buffer
 * pointer is known at the entry, while the size of the data that were read is
 * known at exit.
 *
 * So for each of these generic kprobes, we maintain a retprobe_map. The entry
 * kprobe will first check filters. If the filters match, it will place the
 * required information to the map with a unique id, so that the retprobe map
 * can then check if a value exists (if not, it will just return) and use it to
 * collect its own information (in the case of the read call, it will use the
 * buffer pointer collected at entry to copy the data now that it knows the
 * size.)
 *
 * Originally, we used the threadID as the unique identifier. The problem,
 * however, is for kprobe hooks outside kernel context, such as much of the
 * network stack below tcp and xfrm, this would not work because
 * get_current_pid_tgid returns an error when current is nil -- nil is kernel
 * context. To overcome this, we used the fp which is reliable outside user ctx.
 * One caveat is that it is behind a kernel option CONFIG_FRAME_POINTER. In
 * theory a kernel omit frame-pointers, but we don't have not seen any examples
 * of this.
 *
 * Turns out that using the fp, is also problematic (at least for system calls).
 * Using ctx->bp resulted in many unwanted events from the retprobe. We address
 * this issue by checking first the thread id, and if there is none, we use
 * ctx->bp.
 */
FUNC_INLINE __u64 retprobe_map_get_key(struct pt_regs *ctx)
{
	__u64 ret = get_current_pid_tgid();
	if (ret == (__u64)-22) { // -EINVAL -- current == NULL
		ret = PT_REGS_FP_CORE(ctx);
	}
	return ret;
}

#endif /* __RETPROBE_MAP_H__ */
