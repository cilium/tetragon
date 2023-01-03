// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */
#include "bpf_tracing.h"

#define MAX_TOTAL 9000

static inline __attribute__((always_inline)) int
generic_process_event0(struct pt_regs *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a0;
	int zero = 0;
	/* total is used as a pointer offset so we want type to match
	 * pointer type in order to avoid bit shifts.
	 */
	long ty, total = 0;

	// get e again to help verifier
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	a0 = e->a0;

	e->common.flags = 0;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = ktime_get_ns();

	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->thread_id = retprobe_map_get_key(ctx);

	/* If return arg is needed mark retprobe */
#ifdef GENERIC_KPROBE
	ty = config->argreturn;
	if (ty > 0)
		retprobe_map_set(e->id, e->thread_id, e->common.ktime, 1);
#endif

	/* Read out args1-5 */
	ty = config->arg0;
	if (total < MAX_TOTAL) {
		long errv;
		int a0m;

		a0m = config->arg0m;
		asm volatile("%[a0m] &= 0xffff;\n" ::[a0m] "+r"(a0m)
			     :);

		errv = read_call_arg(ctx, e, 0, ty, total, a0, a0m, map);
		if (errv > 0)
			total += errv;
		/* Follow filter lookup failed so lets abort the event.
		 * From high-level this is a filter and should be in the
		 * filter block, but its just easier to do here so lets
		 * do it where it makes most sense.
		 */
		if (errv < 0)
			return filter_args_reject(e->id);
	}
	e->common.flags = 0;
	e->common.size = total;
	tail_call(ctx, tailcals, 1);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event_and_setup(struct pt_regs *ctx,
				struct bpf_map_def *heap_map,
				struct bpf_map_def *map,
				struct bpf_map_def *tailcals,
				struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	if (config->syscall) {
		struct pt_regs *_ctx;
		_ctx = PT_REGS_SYSCALL_REGS(ctx);
		if (!_ctx)
			return 0;
		e->a0 = PT_REGS_PARM1_CORE_SYSCALL(_ctx);
		e->a1 = PT_REGS_PARM2_CORE_SYSCALL(_ctx);
		e->a2 = PT_REGS_PARM3_CORE_SYSCALL(_ctx);
		e->a3 = PT_REGS_PARM4_CORE_SYSCALL(_ctx);
		e->a4 = PT_REGS_PARM5_CORE_SYSCALL(_ctx);
	} else {
		e->a0 = PT_REGS_PARM1_CORE(ctx);
		e->a1 = PT_REGS_PARM2_CORE(ctx);
		e->a2 = PT_REGS_PARM3_CORE(ctx);
		e->a3 = PT_REGS_PARM4_CORE(ctx);
		e->a4 = PT_REGS_PARM5_CORE(ctx);
	}
	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags = 0;
	return generic_process_event0(ctx, heap_map, map, tailcals, config_map);
}

static inline __attribute__((always_inline)) int
generic_process_event1(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a1;
	int zero = 0;
	long ty, total;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	total = e->common.size;

	a1 = e->a1;

	ty = config->arg1;
	if (total < MAX_TOTAL) {
		long errv;
		int a1m;

		a1m = config->arg1m;
		asm volatile("%[a1m] &= 0xffff;\n" ::[a1m] "+r"(a1m)
			     :);

		errv = read_call_arg(ctx, e, 1, ty, total, a1, a1m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject(e->id);
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 2);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event2(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a2;
	int zero = 0;
	long ty, total;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	total = e->common.size;

	a2 = e->a2;

	ty = config->arg2;
	if (total < MAX_TOTAL) {
		long errv;
		int a2m;

		a2m = config->arg2m;
		asm volatile("%[a2m] &= 0xffff;\n" ::[a2m] "+r"(a2m)
			     :);

		errv = read_call_arg(ctx, e, 2, ty, total, a2, a2m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject(e->id);
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 3);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event3(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a3;
	int zero = 0;
	long ty, total;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	total = e->common.size;

	a3 = e->a3;

	/* Arg filter and copy logic */
	ty = config->arg3;
	if (total < MAX_TOTAL) {
		long errv;
		int a3m;

		a3m = config->arg3m;
		asm volatile("%[a3m] &= 0xffff;\n" ::[a3m] "+r"(a3m)
			     :);

		errv = read_call_arg(ctx, e, 3, ty, total, a3, a3m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject(e->id);
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 4);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event4(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a4;
	int zero = 0;
	long ty, total;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	total = e->common.size;

	a4 = e->a4;

	ty = config->arg4;
	if (total < MAX_TOTAL) {
		long errv;
		int a4m;

		a4m = config->arg4m;
		asm volatile("%[a4m] &= 0xffff;\n" ::[a4m] "+r"(a4m)
			     :);

		errv = read_call_arg(ctx, e, 4, ty, total, a4, a4m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject(e->id);
	}
	e->common.size = total;
	/* Post event */
	total += generic_kprobe_common_size();
	tail_call(ctx, tailcals, 6);
	return 0;
}
