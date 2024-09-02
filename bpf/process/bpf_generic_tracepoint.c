// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"

#define GENERIC_TRACEPOINT

#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"
#include "pfilter.h"
#include "policy_filter.h"

int generic_tracepoint_process_event(void *ctx);
int generic_tracepoint_filter(void *ctx);
int generic_tracepoint_arg(void *ctx);
int generic_tracepoint_actions(void *ctx);
int generic_tracepoint_output(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} tp_calls SEC(".maps") = {
	.values = {
		[1] = (void *)&generic_tracepoint_process_event,
		[2] = (void *)&generic_tracepoint_filter,
		[3] = (void *)&generic_tracepoint_arg,
		[4] = (void *)&generic_tracepoint_actions,
		[5] = (void *)&generic_tracepoint_output,
	},
};

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
	__type(key, __u32);
	__type(value, struct event_config);
} config_map SEC(".maps");

static struct generic_maps maps = {
	.heap = (struct bpf_map_def *)&tp_heap,
	.calls = (struct bpf_map_def *)&tp_calls,
	.filter = (struct bpf_map_def *)&filter_map,
};

struct generic_tracepoint_event_arg {
	/* common header */
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	/* tracepoint specific fields ... */
};

FUNC_INLINE unsigned long get_ctx_ul(void *src, int type)
{
	switch (type) {
	case syscall64_type:
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

	case char_buf:
	case string_type: {
		char *buff;
		probe_read(&buff, sizeof(char *), src);
		return (unsigned long)buff;
	}

	case data_loc_type: {
		u32 ret;

		probe_read(&ret, sizeof(ret), src);
		return ret;
	}

	case const_buf_type: {
		return (unsigned long)src;
	}

	case skb_type: {
		struct sk_buff *skb;

		probe_read(&skb, sizeof(struct sk_buff *), src);
		return (unsigned long)skb;
	}

	case sock_type: {
		struct sock *sk;

		probe_read(&sk, sizeof(struct sock *), src);
		return (unsigned long)sk;
	}

	default:
	case nop_ty:
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

	/* check policy filter */
	if (!policy_filter_check(config->policy_id))
		return 0;

	/* Tail call into filters. */
	msg->idx = 0;
	msg->func_id = config->func_id;
	msg->retprobe_id = 0;

	msg->a0 = ({
		unsigned long ctx_off = config->t_arg0_ctx_off;
		int ty = config->arg0;
		asm volatile("%[ctx_off] &= 0xffff;\n"
			     : [ctx_off] "+r"(ctx_off));
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a1 = ({
		unsigned long ctx_off = config->t_arg1_ctx_off;
		int ty = config->arg1;
		asm volatile("%[ctx_off] &= 0xffff;\n"
			     : [ctx_off] "+r"(ctx_off));
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a2 = ({
		unsigned long ctx_off = config->t_arg2_ctx_off;
		int ty = config->arg2;
		asm volatile("%[ctx_off] &= 0xffff;\n"
			     : [ctx_off] "+r"(ctx_off));
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a3 = ({
		unsigned long ctx_off = config->t_arg3_ctx_off;
		int ty = config->arg3;
		asm volatile("%[ctx_off] &= 0xffff;\n"
			     : [ctx_off] "+r"(ctx_off));
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	msg->a4 = ({
		unsigned long ctx_off = config->t_arg4_ctx_off;
		int ty = config->arg4;
		asm volatile("%[ctx_off] &= 0xffff;\n"
			     : [ctx_off] "+r"(ctx_off));
		get_ctx_ul((char *)ctx + ctx_off, ty);
	});

	generic_process_init(msg, MSG_OP_GENERIC_TRACEPOINT, config);

	msg->common.op = MSG_OP_GENERIC_TRACEPOINT;
	msg->sel.curr = 0;
	msg->tailcall_index_process = 0;
	msg->tailcall_index_selector = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	msg->sel.pass = false;
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
	tail_call(ctx, &tp_calls, TAIL_CALL_FILTER);
	return 0;
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_process_event(void *ctx)
{
	return generic_process_event(ctx, (struct bpf_map_def *)&tp_heap,
				     (struct bpf_map_def *)&tp_calls,
				     (struct bpf_map_def *)&config_map, 0);
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter((struct bpf_map_def *)&tp_heap,
				     (struct bpf_map_def *)&filter_map);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &tp_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &tp_calls, TAIL_CALL_PROCESS);
	/* If filter does not accept drop it. Ideally we would
	 * log error codes for later review, TBD.
	 */
	return PFILTER_REJECT;
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_arg(void *ctx)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&tp_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&tp_calls,
			       (struct bpf_map_def *)&config_map,
			       true);
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_actions(void *ctx)
{
	return generic_actions(ctx, &maps);
}

__attribute__((section("tracepoint"), used)) int
generic_tracepoint_output(void *ctx)
{
	return generic_output(ctx, (struct bpf_map_def *)&tp_heap, MSG_OP_GENERIC_TRACEPOINT);
}

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
