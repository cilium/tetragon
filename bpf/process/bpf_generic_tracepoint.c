// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 11);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} tp_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} tp_heap SEC(".maps");

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event_config);
} config_map SEC(".maps");

struct generic_tracepoint_event_arg {
	/* common header */
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	/* tracepoint specific fields ... */
};

static inline __attribute__((always_inline)) unsigned long get_ctx_ul(void *src,
								      int type)
{
	switch (type) {
	case nop_s64_ty:
	case nop_u64_ty:
	case s64_ty:
	case u64_ty: {
		u64 ret;
		probe_read(&ret, sizeof(u64), src);
		return ret;
	}

	case size_type: {
		size_t ret;
		probe_read(&ret, sizeof(size_t), src);
		return (unsigned long)ret;
	}

	case nop_s32_ty:
	case s32_ty: {
		s32 ret;
		probe_read(&ret, sizeof(u32), src);
		return ret;
	}

	case nop_u32_ty:
	case u32_ty: {
		u32 ret;
		probe_read(&ret, sizeof(u32), src);
		return ret;
	}

	case char_buf: {
		char *buff;
		probe_read(&buff, sizeof(char *), src);
		return (unsigned long)buff;
	}

	case const_buf_type: {
		return (unsigned long)src;
	}

	default:
	case nop:
		return 0;
	}
}

__attribute__((section("tracepoint/generic_tracepoint"), used)) int
generic_tracepoint_event(struct generic_tracepoint_event_arg *ctx)
{
	struct msg_generic_kprobe *msg;
	struct task_struct *task;
	struct event_config *config;
	int zero = 0, i;

	msg = map_lookup_elem(&tp_heap, &zero);
	if (!msg)
		return 0;

	config = map_lookup_elem(&config_map, &zero);
	if (!config)
		return 0;

	msg->a0 = ({
		unsigned long ctx_off = config->t_arg0_ctx_off;
		int ty = config->arg0;
		asm volatile("%[ctx_off] &= 0xffff;\n" ::[ctx_off] "+r"(ctx_off)
			     :);
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a1 = ({
		unsigned long ctx_off = config->t_arg1_ctx_off;
		int ty = config->arg1;
		asm volatile("%[ctx_off] &= 0xffff;\n" ::[ctx_off] "+r"(ctx_off)
			     :);
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a2 = ({
		unsigned long ctx_off = config->t_arg2_ctx_off;
		int ty = config->arg2;
		asm volatile("%[ctx_off] &= 0xffff;\n" ::[ctx_off] "+r"(ctx_off)
			     :);
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a3 = ({
		unsigned long ctx_off = config->t_arg3_ctx_off;
		int ty = config->arg3;
		asm volatile("%[ctx_off] &= 0xffff;\n" ::[ctx_off] "+r"(ctx_off)
			     :);
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a4 = ({
		unsigned long ctx_off = config->t_arg4_ctx_off;
		int ty = config->arg4;
		asm volatile("%[ctx_off] &= 0xffff;\n" ::[ctx_off] "+r"(ctx_off)
			     :);
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->common.op = MSG_OP_GENERIC_TRACEPOINT;
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	msg->sel.pass = 0;
	task = (struct task_struct *)get_current_task();
	/* Initialize namespaces to apply filters on them */
	get_namespaces(&msg->ns, task);
	/* Initialize capabilities to apply filters on them */
	get_current_subj_caps(&msg->caps, task);
#ifdef __NS_CHANGES_FILTER
	msg->sel.match_ns = 0;
#endif
#ifdef __CAP_CHANGES_FILTER
	msg->sel.match_cap = 0;
#endif
	/* Tail call into filters. */
	msg->idx = 0;
	tail_call(ctx, &tp_calls, 5);
	return 0;
}

__attribute__((section("tracepoint/0"), used)) int
generic_tracepoint_event0(void *ctx)
{
	return generic_process_event0(ctx, (struct bpf_map_def *)&tp_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&tp_calls,
				      (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/1"), used)) int
generic_tracepoint_event1(void *ctx)
{
	return generic_process_event1(ctx, (struct bpf_map_def *)&tp_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&tp_calls,
				      (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/2"), used)) int
generic_tracepoint_event2(void *ctx)
{
	return generic_process_event2(ctx, (struct bpf_map_def *)&tp_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&tp_calls,
				      (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/3"), used)) int
generic_tracepoint_event3(void *ctx)
{
	return generic_process_event3(ctx, (struct bpf_map_def *)&tp_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&tp_calls,
				      (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/4"), used)) int
generic_tracepoint_event4(void *ctx)
{
	return generic_process_event4(ctx, (struct bpf_map_def *)&tp_heap,
				      (struct bpf_map_def *)&filter_map,
				      (struct bpf_map_def *)&tp_calls,
				      (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/5"), used)) int
generic_tracepoint_filter(void *ctx)
{
	struct msg_generic_kprobe *msg;
	int ret, zero = 0;

	msg = map_lookup_elem(&tp_heap, &zero);
	if (!msg)
		return 0;

	ret = generic_process_filter(&msg->sel, &msg->current, &msg->ns,
				     &msg->caps, &filter_map, msg->idx);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &tp_calls, 5);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &tp_calls, 0);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

// Filter tailcalls: tracepoint/6...tracepoint/10
// see also: MIN_FILTER_TAILCALL, MAX_FILTER_TAILCALL

__attribute__((section("tracepoint/6"), used)) int
generic_tracepoint_arg1(void *ctx)
{
	return filter_read_arg(ctx, 0, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls, (void *)0,
			       (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/7"), used)) int
generic_tracepoint_arg2(void *ctx)
{
	return filter_read_arg(ctx, 1, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls, (void *)0,
			       (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/8"), used)) int
generic_tracepoint_arg3(void *ctx)
{
	return filter_read_arg(ctx, 2, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls, (void *)0,
			       (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/9"), used)) int
generic_tracepoint_arg4(void *ctx)
{
	return filter_read_arg(ctx, 3, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls, (void *)0,
			       (struct bpf_map_def *)&config_map);
}

__attribute__((section("tracepoint/10"), used)) int
generic_tracepoint_arg5(void *ctx)
{
	return filter_read_arg(ctx, 4, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls, (void *)0,
			       (struct bpf_map_def *)&config_map);
}

char _license[] __attribute__((section("license"), used)) = "GPL";
