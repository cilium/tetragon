// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __GENERIC_CALLS_H__
#define __GENERIC_CALLS_H__

#include "bpf_tracing.h"

#define MAX_TOTAL 9000

static inline __attribute__((always_inline)) int
generic_process_event(void *ctx, int index, struct bpf_map_def *heap_map,
		      struct bpf_map_def *tailcals, struct bpf_map_def *config_map,
		      struct bpf_map_def *data_heap)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	unsigned long a;
	int zero = 0;
	long ty, total;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

	a = (&e->a0)[index];
	total = e->common.size;

	/* Read out args1-5 */
	ty = (&config->arg0)[index];
	if (total < MAX_TOTAL) {
		long errv;
		int am;

		am = (&config->arg0m)[index];
		asm volatile("%[am] &= 0xffff;\n" ::[am] "+r"(am)
			     :);

		errv = read_call_arg(ctx, e, index, ty, total, a, am, data_heap);
		if (errv > 0)
			total += errv;
		/* Follow filter lookup failed so lets abort the event.
		 * From high-level this is a filter and should be in the
		 * filter block, but its just easier to do here so lets
		 * do it where it makes most sense.
		 */
		if (errv < 0)
			return filter_args_reject(e->func_id);
	}
	e->common.size = total;
	/* Continue to process other arguments. */
	if (index < 4)
		tail_call(ctx, tailcals, index + 1);

	/* Last argument, go send.. */
	tail_call(ctx, tailcals, 6);
	return 0;
}

static inline __attribute__((always_inline)) void
generic_process_init(struct msg_generic_kprobe *e, u8 op, struct event_config *config)
{
	e->common.op = op;

	e->common.flags = 0;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = ktime_get_ns();

	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->action = 0;

	/**
	 * Per thread tracking rules TID is the calling thread:
	 *  At kprobes, tracpoints etc we report the calling thread ID to user space.
	 */
	e->tid = (__u32)get_current_pid_tgid();
}

static inline __attribute__((always_inline)) int
generic_process_event_and_setup(struct pt_regs *ctx,
				struct bpf_map_def *heap_map,
				struct bpf_map_def *tailcals,
				struct bpf_map_def *config_map,
				struct bpf_map_def *data_heap)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	long ty __maybe_unused;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;

#ifdef GENERIC_KPROBE
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

	generic_process_init(e, MSG_OP_GENERIC_KPROBE, config);

	e->retprobe_id = retprobe_map_get_key(ctx);

	/* If return arg is needed mark retprobe */
	ty = config->argreturn;
	if (ty > 0)
		retprobe_map_set(e->func_id, e->retprobe_id, e->common.ktime, 1);
#endif

#ifdef GENERIC_UPROBE
	/* no arguments for uprobes for now */
	e->a0 = 0;
	e->a1 = 0;
	e->a2 = 0;
	e->a3 = 0;
	e->a4 = 0;
	generic_process_init(e, MSG_OP_GENERIC_UPROBE, config);
#endif

	return generic_process_event(ctx, 0, heap_map, tailcals, config_map, data_heap);
}

#endif /* __GENERIC_CALLS_H__ */
