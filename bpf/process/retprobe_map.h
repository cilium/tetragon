// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */
#include "bpf_tracing.h"

struct retprobe_info {
	unsigned long ptr;
	unsigned long cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct retprobe_info);
} retprobe_map SEC(".maps");

static inline __attribute__((always_inline)) unsigned long
retprobe_map_get(__u64 tid, unsigned long *cntp)
{
	struct retprobe_info *info;
	unsigned long ptr;

	info = map_lookup_elem(&retprobe_map, &tid);
	if (!info)
		return 0;

	ptr = info->ptr;
	if (cntp)
		*cntp = info->cnt;
	map_delete_elem(&retprobe_map, &tid);
	return ptr;
}

static inline __attribute__((always_inline)) void retprobe_map_clear(__u64 tid)
{
	struct retprobe_info *info = map_lookup_elem(&retprobe_map, &tid);

	if (info)
		map_delete_elem(&retprobe_map, &tid);
}

static inline __attribute__((always_inline)) void
retprobe_map_set(__u64 tid, unsigned long ptr)
{
	struct retprobe_info info = {
		.ptr = ptr,
	};

	map_update_elem(&retprobe_map, &tid, &info, BPF_ANY);
}

static inline __attribute__((always_inline)) void
retprobe_map_set_iovec(__u64 tid, unsigned long ptr, unsigned long cnt)
{
	struct retprobe_info info = {
		.ptr = ptr,
		.cnt = cnt,
	};

	map_update_elem(&retprobe_map, &tid, &info, BPF_ANY);
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
static inline __attribute__((always_inline)) __u64
retprobe_map_get_key(struct pt_regs *ctx)
{
	__u64 ret = get_current_pid_tgid();
	if (ret == (__u64)-22) { // -EINVAL -- current == NULL
		ret = PT_REGS_FP_CORE(ctx);
	}
	return ret;
}
