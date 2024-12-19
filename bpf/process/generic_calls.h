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
generic_start_process_filter(void *ctx, struct bpf_map_def *calls)
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
	tail_call(ctx, calls, TAIL_CALL_FILTER);
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

FUNC_LOCAL __u32
do_action(void *ctx, __u32 i, struct selector_action *actions, bool *post)
{
	int signal __maybe_unused = FGS_SIGKILL;
	int action = actions->act[i];
	struct msg_generic_kprobe *e;
	__s32 error, *error_p;
	int fdi, namei;
	int newfdi, oldfdi;
	int socki;
	int argi __maybe_unused;
	int err = 0;
	int zero = 0;
	__u64 id;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	switch (action) {
	case ACTION_NOPOST:
		*post = false;
		break;
	case ACTION_POST: {
		__u64 ratelimit_interval __maybe_unused = actions->act[++i];
		__u64 ratelimit_scope __maybe_unused = actions->act[++i];
#ifdef __LARGE_BPF_PROG
		if (rate_limit(ratelimit_interval, ratelimit_scope, e))
			*post = false;
#endif /* __LARGE_BPF_PROG */
		__u32 kernel_stack_trace = actions->act[++i];

		if (kernel_stack_trace) {
			// Stack id 0 is valid so we need a flag.
			e->common.flags |= MSG_COMMON_FLAG_KERNEL_STACKTRACE;
			// We could use BPF_F_REUSE_STACKID to override old with new stack if
			// same stack id. It means that if we have a collision and user space
			// reads the old one too late, we are reading the wrong stack (the new,
			// old one was overwritten).
			//
			// Here we just signal that there was a collision returning -EEXIST.
			e->kernel_stack_id = get_stackid(ctx, &stack_trace_map, 0);
		}

		__u32 user_stack_trace = actions->act[++i];

		if (user_stack_trace) {
			e->common.flags |= MSG_COMMON_FLAG_USER_STACKTRACE;
			e->user_stack_id = get_stackid(ctx, &stack_trace_map, BPF_F_USER_STACK);
		}
#ifdef __LARGE_MAP_KEYS
		__u32 ima_hash = actions->act[++i];

		if (ima_hash)
			e->common.flags |= MSG_COMMON_FLAG_IMA_HASH;
#endif
		break;
	}

	case ACTION_UNFOLLOWFD:
	case ACTION_FOLLOWFD:
		fdi = actions->act[++i];
		namei = actions->act[++i];
		err = installfd(e, fdi, namei, action == ACTION_FOLLOWFD);
		break;
	case ACTION_COPYFD:
		oldfdi = actions->act[++i];
		newfdi = actions->act[++i];
		err = copyfd(e, oldfdi, newfdi);
		break;
	case ACTION_SIGNAL:
		signal = actions->act[++i];
	case ACTION_SIGKILL:
		do_action_signal(signal);
		break;
	case ACTION_OVERRIDE:
		error = actions->act[++i];
		id = get_current_pid_tgid();

		/*
		 * TODO: this should not happen, it means that the override
		 * program was not executed for some reason, we should do
		 * warning in here
		 */
		error_p = map_lookup_elem(&override_tasks, &id);
		if (error_p)
			*error_p = error;
		else
			map_update_elem(&override_tasks, &id, &error, BPF_ANY);
		break;
	case ACTION_GETURL:
	case ACTION_DNSLOOKUP:
		/* Set the URL or DNS action */
		e->action_arg_id = actions->act[++i];
		break;
	case ACTION_TRACKSOCK:
	case ACTION_UNTRACKSOCK:
		socki = actions->act[++i];
		err = tracksock(e, socki, action == ACTION_TRACKSOCK);
		break;
	case ACTION_NOTIFY_ENFORCER:
		error = actions->act[++i];
		signal = actions->act[++i];
		argi = actions->act[++i];
		do_action_notify_enforcer(e, error, signal, argi);
		break;
	case ACTION_CLEANUP_ENFORCER_NOTIFICATION:
		do_enforcer_cleanup();
	default:
		break;
	}
	if (!err) {
		e->action = action;
		return ++i;
	}
	return 0;
}

FUNC_INLINE bool
has_action(struct selector_action *actions, __u32 idx)
{
	__u32 offset = idx * sizeof(__u32) + sizeof(*actions);

	return offset < actions->actionlen;
}

/* Currently supporting 2 actions for selector. */
FUNC_INLINE bool
do_actions(void *ctx, struct selector_action *actions)
{
	bool post = true;
	__u32 l, i = 0;

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (l = 0; l < MAX_ACTIONS; l++) {
		if (!has_action(actions, i))
			break;
		i = do_action(ctx, i, actions, &post);
	}

	return post;
}

FUNC_INLINE long
generic_actions(void *ctx, struct bpf_map_def *calls)
{
	struct selector_arg_filters *arg;
	struct selector_action *actions;
	struct msg_generic_kprobe *e;
	int actoff, pass, zero = 0;
	bool postit;
	__u8 *f;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	pass = e->pass;
	if (pass <= 1)
		return 0;

	f = map_lookup_elem(&filter_map, &e->idx);
	if (!f)
		return 0;

	asm volatile("%[pass] &= 0x7ff;\n"
		     : [pass] "+r"(pass)
		     :);
	arg = (struct selector_arg_filters *)&f[pass];

	actoff = pass + arg->arglen;
	asm volatile("%[actoff] &= 0x7ff;\n"
		     : [actoff] "+r"(actoff)
		     :);
	actions = (struct selector_action *)&f[actoff];

	postit = do_actions(ctx, actions);
	if (postit)
		tail_call(ctx, calls, TAIL_CALL_SEND);
	return postit;
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

FUNC_INLINE int generic_retkprobe(void *ctx, struct bpf_map_def *calls, unsigned long ret)
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
		size += read_call_arg(ctx, e, 0, ty_arg, size, ret, 0, data_heap_ptr);
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
		size += __copy_char_buf(ctx, size, info.ptr, ret, false, e, data_heap_ptr);
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

	tail_call(ctx, calls, TAIL_CALL_ARGS);
	return 1;
}
#endif /* __GENERIC_CALLS_H__ */
