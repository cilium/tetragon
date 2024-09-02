// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_KRETPROBE

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

int generic_retkprobe_filter_arg(struct pt_regs *ctx);
int generic_retkprobe_actions(struct pt_regs *ctx);
int generic_retkprobe_output(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 6);
	__uint(key_size, sizeof(__u32));
	__array(values, int(struct pt_regs *));
} retkprobe_calls SEC(".maps") = {
	.values = {
		[3] = (void *)&generic_retkprobe_filter_arg,
		[4] = (void *)&generic_retkprobe_actions,
		[5] = (void *)&generic_retkprobe_output,
	},
};

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_config);
} config_map SEC(".maps");

#ifdef __LARGE_BPF_PROG
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");
#define data_heap_ptr &data_heap
#else
#define data_heap_ptr 0
#endif

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/generic_retkprobe"
#else
#define MAIN "kprobe/generic_retkprobe"
#endif

static struct generic_maps maps = {
	.heap = (struct bpf_map_def *)&process_call_heap,
	.calls = (struct bpf_map_def *)&retkprobe_calls,
	.filter = (struct bpf_map_def *)&filter_map,
};

__attribute__((section((MAIN)), used)) int
BPF_KRETPROBE(generic_retkprobe_event, unsigned long ret)
{
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct retprobe_info info;
	struct event_config *config;
	bool walker = false;
	int zero = 0;
	__u32 ppid;
	long size = 0;
	long ty_arg, do_copy;
	__u64 pid_tgid;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	e->idx = get_index(ctx);

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

	e->func_id = config->func_id;
	e->retprobe_id = retprobe_map_get_key(ctx);
	pid_tgid = get_current_pid_tgid();
	e->tid = (__u32)pid_tgid;

	if (!retprobe_map_get(e->func_id, e->retprobe_id, &info))
		return 0;

	*(unsigned long *)e->args = info.ktime_enter;
	size += sizeof(info.ktime_enter);

	ty_arg = config->argreturn;
	do_copy = config->argreturncopy;
	if (ty_arg) {
		size += read_call_arg(ctx, e, 0, ty_arg, size, ret, 0, (struct bpf_map_def *)data_heap_ptr);
#ifdef __LARGE_BPF_PROG
		struct socket_owner owner;
		switch (config->argreturnaction) {
		case ACTION_TRACKSOCK:
			owner.pid = e->current.pid;
			owner.tid = e->tid;
			owner.ktime = e->current.ktime;
			map_update_elem(&socktrack_map, &ret, &owner, BPF_ANY);
			break;
		case ACTION_UNTRACKSOCK:
			map_delete_elem(&socktrack_map, &ret);
			break;
		}
#endif
	}

	/*
	 * 0x1000 should be maximum argument length, so masking
	 * with 0x1fff is safe and verifier will be happy.
	 */
	asm volatile("%[size] &= 0x1fff;\n"
		     : [size] "+r"(size));

	switch (do_copy) {
	case char_buf:
		size += __copy_char_buf(ctx, size, info.ptr, ret, false, e, (struct bpf_map_def *)data_heap_ptr);
		break;
	case char_iovec:
		size += __copy_char_iovec(size, info.ptr, info.cnt, ret, e);
	default:
		break;
	}

	/* Complete message header and send */
	enter = event_find_curr(&ppid, &walker);

	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags |= MSG_COMMON_FLAG_RETURN;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = size;
	e->common.ktime = ktime_get_ns();

	if (enter) {
		e->current.pid = enter->key.pid;
		e->current.ktime = enter->key.ktime;
	}
	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->func_id = config->func_id;
	e->common.size = size;

	tail_call(ctx, &retkprobe_calls, TAIL_CALL_ARGS);
	return 1;
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_filter_arg)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&retkprobe_calls,
			       (struct bpf_map_def *)&config_map,
			       false);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_actions)
{
	return generic_actions(ctx, &maps);
}

__attribute__((section("kprobe"), used)) int
BPF_KRETPROBE(generic_retkprobe_output)
{
	return generic_output(ctx, (struct bpf_map_def *)&process_call_heap, MSG_OP_GENERIC_KPROBE);
}
