// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "retprobe_map.h"
#include "types/basic.h"
#include "data_event.h"
#include "full_copy.h"

#define MAX_FILENAME 8096

char _license[] __attribute__((section(("license")), used)) = "GPL";

struct bpf_map_def __attribute__((section("maps"), used)) process_call_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_generic_kprobe),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) retkprobe_calls = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) data_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_data),
	.max_entries = 1,
};

__attribute__((section(("kprobe/generic_retkprobe")), used)) int
generic_kprobe_event(struct pt_regs *ctx)
{
	enum generic_func_args_enum tetragon_args;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct retprobe_info info;
	bool walker = false;
	int zero = 0;
	__u32 ppid;
	long total = 0;
	long size = 0;
	long ty_arg, do_copy;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	e->thread_id = retprobe_map_get_key(ctx);
	full_copy_init(e);

	if (!retprobe_map_get(e->thread_id, &info))
		return 0;

	ty_arg = bpf_core_enum_value(tetragon_args, argreturn);
	do_copy = bpf_core_enum_value(tetragon_args, argreturncopy);
	if (ty_arg)
		size += read_call_arg(ctx, e, 0, ty_arg, 0,
				      (unsigned long)ctx->ax, 0, 0);
	switch (do_copy) {
	case char_buf:
		size += __copy_char_buf(size, info.ptr, ctx->ax, e,
					info.fullCopy);
		break;
	case char_iovec:
		size += __copy_char_iovec(size, info.ptr, info.cnt, ctx->ax, e,
					  info.fullCopy);
	default:
		break;
	}

	/* Complete message header and send */
	enter = event_find_curr(&ppid, 0, &walker);

	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags = 1;
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

	e->id = bpf_core_enum_value(tetragon_args, func_id);

	total = size;
	total += generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     :
		     : [total] "+r"(total)
		     :);
	e->common.size = total;

	if (e->full_copy.cnt) {
		tail_call(ctx, &retkprobe_calls, 0);
		return 2;
	}

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 0;
}

__attribute__((section(("kprobe/0")), used)) int
generic_retkprobe_full_copy(void *ctx)
{
	return full_copy(ctx, &process_call_heap, &data_heap);
}
