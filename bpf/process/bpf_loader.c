// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "types/probe_read_kernel_or_user.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_event.h"
#include "bpf_task.h"

struct msg_loader {
	struct msg_common common;
	struct msg_execve_key current;
	__u32 pid;
	__u32 buildid_size;
	__u32 path_size;
	char buildid[20];
	char path[4096];
	void *pe;
};

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_loader);
} loader_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ids_map SEC(".maps");

struct __perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 bits;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct __perf_event_attr);
} attr_heap SEC(".maps");

#define VM_EXEC 0x00000004

#define ATTR_BIT_MMAP	 BIT_ULL(8)
#define ATTR_BIT_MMAP2	 BIT_ULL(23)
#define ATTR_BIT_BUILDID BIT_ULL(34)

__attribute__((section(("kprobe/perf_event_mmap_output")), used)) int
loader_kprobe(struct pt_regs *ctx)
{
	struct perf_mmap_event *mmap_event;
	struct execve_map_value *curr;
	struct task_struct *current;
	struct msg_loader *msg;
	struct perf_event *pe;
	__u64 *id_map, id_pe;
	const char *path;
	size_t total;
	int tgid;
	long len;

	msg = map_lookup_elem(&loader_heap, &(__u32){ 0 });
	if (!msg)
		return 0;

	pe = (struct perf_event *)PT_REGS_PARM1_CORE(ctx);

	/* Make sure it's our event that triggered perf_event_mmap_output,
	 * to have all the needed info.
	 */
	if (!msg->pe) {
		id_map = map_lookup_elem(&ids_map, &(__u32){ 0 });
		if (!id_map)
			return 0;
		id_pe = BPF_CORE_READ(pe, id);
		if (*id_map != id_pe)
			return 0;
		msg->pe = pe;
	} else if (msg->pe != pe) {
		return 0;
	}

	current = (struct task_struct *)get_current_task();
	tgid = BPF_CORE_READ(current, tgid);

	curr = execve_map_get_noinit(tgid);
	if (!curr)
		return 0;

	msg->current.pid = curr->key.pid;
	msg->current.ktime = curr->key.ktime;

	mmap_event = (struct perf_mmap_event *)PT_REGS_PARM2_CORE(ctx);

	/* Send all events with valid build id, user space will sort
	 * out duplicates.
	 */
	msg->buildid_size = BPF_CORE_READ(mmap_event, build_id_size);
	if (!msg->buildid_size)
		return 0;

	probe_read_kernel(&msg->buildid[0], sizeof(msg->buildid),
			  _(&mmap_event->build_id[0]));

	path = BPF_CORE_READ(mmap_event, file_name);
	len = probe_read_kernel_str(&msg->path, sizeof(msg->path), path);
	msg->path_size = (__u32)len;

	msg->pid = tgid;

	total = offsetof(struct msg_loader, pe);
	msg->common.size = total;
	msg->common.ktime = ktime_get_ns();
	msg->common.op = MSG_OP_LOADER;
	msg->common.flags = 0;

	perf_event_output_metric(ctx, MSG_OP_LOADER, &tcpmon_map, BPF_F_CURRENT_CPU, msg, total);
	return 0;
}
