// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_CALLS_H__
#define __GENERIC_CALLS_H__

#include "bpf_tracing.h"
#include "pfilter.h"
#include "policy_filter.h"
#include "types/basic.h"
#include "vmlinux.h"

#define MAX_TOTAL 9000

FUNC_INLINE int
generic_start_process_filter(void *ctx, struct generic_maps *maps)
{
	struct msg_generic_kprobe *msg;
	struct event_config *config;
	struct task_struct *task;
	int i, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	/* setup index, check policy filter, and setup function id */
	msg->idx = get_index(ctx);
	config = map_lookup_elem(&config_map, &msg->idx);
	if (!config)
		return 0;
	if (!policy_filter_check(config->policy_id))
		return 0;
	msg->func_id = config->func_id;
	msg->retprobe_id = 0;

	/* Initialize selector index to 0 */
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	/* Initialize accept field to reject */
	msg->sel.pass = false;
	msg->tailcall_index_process = 0;
	msg->tailcall_index_selector = 0;
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

	msg->lsm.post = false;

	/* Tail call into filters. */
	tail_call(ctx, maps->calls, TAIL_CALL_FILTER);
	return 0;
}

FUNC_INLINE int
generic_process_event(void *ctx, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int index, zero = 0;
	unsigned long a;
	long ty, total;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

	index = e->tailcall_index_process;
	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));

	a = (&e->a0)[index];
	total = e->common.size;

	/* Read out args1-5 */
	ty = (&config->arg0)[index];
	if (total < MAX_TOTAL) {
		long errv;
		int am;

		am = (&config->arg0m)[index];
		asm volatile("%[am] &= 0xffff;\n"
			     : [am] "+r"(am));

		errv = read_call_arg(ctx, e, index, ty, total, a, am, data_heap_ptr);
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
	if (index < 4) {
		e->tailcall_index_process = index + 1;
		tail_call(ctx, tailcals, TAIL_CALL_PROCESS);
	}

	/* Last argument, go send.. */
	e->tailcall_index_process = 0;
	tail_call(ctx, tailcals, TAIL_CALL_ARGS);
	return 0;
}

FUNC_INLINE void
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

FUNC_INLINE int
generic_process_event_and_setup(struct pt_regs *ctx, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	long ty __maybe_unused;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(&config_map, &e->idx);
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

#ifdef GENERIC_LSM
	struct bpf_raw_tracepoint_args *raw_args = (struct bpf_raw_tracepoint_args *)ctx;

	e->a0 = BPF_CORE_READ(raw_args, args[0]);
	e->a1 = BPF_CORE_READ(raw_args, args[1]);
	e->a2 = BPF_CORE_READ(raw_args, args[2]);
	e->a3 = BPF_CORE_READ(raw_args, args[3]);
	e->a4 = BPF_CORE_READ(raw_args, args[4]);
	generic_process_init(e, MSG_OP_GENERIC_LSM, config);
#endif

#ifdef GENERIC_UPROBE
	/* no arguments for uprobes for now */
	e->a0 = PT_REGS_PARM1_CORE(ctx);
	e->a1 = PT_REGS_PARM2_CORE(ctx);
	e->a2 = PT_REGS_PARM3_CORE(ctx);
	e->a3 = PT_REGS_PARM4_CORE(ctx);
	e->a4 = PT_REGS_PARM5_CORE(ctx);
	generic_process_init(e, MSG_OP_GENERIC_UPROBE, config);
#endif

	return generic_process_event(ctx, tailcals);
}

FUNC_INLINE long
generic_output(void *ctx, u8 op)
{
	struct msg_generic_kprobe *e;
	int zero = 0;
	size_t total;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

/* We don't need this data in return kprobe event */
#ifndef GENERIC_KRETPROBE
#ifdef __NS_CHANGES_FILTER
	/* update the namespaces if we matched a change on that */
	if (e->sel.match_ns) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_namespaces(&enter->ns, task);
	}
#endif
#ifdef __CAP_CHANGES_FILTER
	/* update the capabilities if we matched a change on that */
	if (e->sel.match_cap) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_current_subj_caps(&enter->caps, task);
	}
#endif
#endif // !GENERIC_KRETPROBE

	total = e->common.size + generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     : [total] "+r"(total));
	perf_event_output_metric(ctx, op, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 0;
}

#endif /* __GENERIC_CALLS_H__ */
