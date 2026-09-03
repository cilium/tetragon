// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_rate.h"
#include "process.h"
#include "bpf_process_event.h"
#include "bpf_ktime.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

FUNC_INLINE void
event_exit_fill(struct msg_exit *exit, __u32 tgid, __u64 enter_ktime,
		struct task_struct *task)
{
	exit->common.op = MSG_OP_EXIT;
	exit->common.flags = 0;
	exit->common.pad[0] = 0;
	exit->common.pad[1] = 0;
	exit->common.size = sizeof(*exit);
	exit->common.ktime = tg_get_ktime();

	exit->current.pid = tgid;
	exit->current.pad[0] = 0;
	exit->current.pad[1] = 0;
	exit->current.pad[2] = 0;
	exit->current.pad[3] = 0;
	exit->current.ktime = enter_ktime;

	/**
	 * Per thread tracking rules TID == PID :
	 *  We want the exit event to match the exec one, and since during exec
	 *  we report the thread group leader, do same here as we read the exec
	 *  entry from the execve_map anyway and explicitly set it to the to tgid.
	 */
	exit->info.tid = tgid;
	with_errmetrics(probe_read, &exit->info.code, sizeof(exit->info.code),
			_(&task->exit_code));
}

#ifdef __V511_BPF_PROG
FUNC_INLINE int
rb_exit_output(void *ctx, struct execve_map_value *enter, __u32 tgid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_exit *exit;

	exit = event_ringbuf_reserve(MSG_OP_EXIT, sizeof(struct msg_exit));
	if (!exit)
		return 0;
	event_exit_fill(exit, tgid, enter->key.ktime, task);
	ringbuf_submit(exit, 0);
	return 0;
}
#endif

FUNC_INLINE void
perf_exit__output(void *ctx, struct execve_map_value *enter, __u32 tgid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_exit exit;

	event_exit_fill(&exit, tgid, enter->key.ktime, task);
	event_output_metric(ctx, MSG_OP_EXIT, &exit, sizeof(struct msg_exit));
}

FUNC_INLINE void event_exit_send(void *ctx, __u32 tgid)
{
	struct execve_map_value *enter;

	/* It is safe to do a map_lookup_event() here because
	 * we must have captured the execve case in order for an
	 * exit to happen. Or in the FGS startup case we pre
	 * populated it before loading BPF programs. At any rate
	 * if the entry is _not_ in the execve_map the lookup
	 * will create an empty entry, the ktime check below will
	 * catch it and we will quickly delete the entry again.
	 */
	enter = execve_map_get_noinit(tgid);
	if (!enter)
		return;
	if (enter->key.ktime) {
#ifdef __V511_BPF_PROG
		if (!CONFIG(USE_PERF_RING_BUF))
			rb_exit_output(ctx, enter, tgid);
		else
#endif
			perf_exit__output(ctx, enter, tgid);
	}

	execve_map_delete(tgid);
	map_delete_elem(&tg_parents_bin, &enter->key.pid);
}

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's initialized for thread leader:
 *
 *   clone {
 *     copy_process
 *       copy_signal
 *         atomic_set(&sig->live, 1);
 *   }
 *
 * Incremented for each new thread:
 *
 *   clone {
 *     copy_process
 *       atomic_inc(&current->signal->live);
 *     ...
 *     wake_up_new_task
 *   }
 *
 * Decremented for each exiting thread:
 *
 *   do_exit {
 *     group_dead = atomic_dec_and_test(&tsk->signal->live);
 *     ...
 *     if (group_dead)
 *              acct_process();
 *     ...
 *   }
 *
 * Hooking to acct_process we ensure tsk->signal->live is 0 and
 * we are the last one of the thread group.
 */
__attribute__((section("kprobe/acct_process"), used)) int
event_exit_acct_process(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();

	event_exit_send(ctx, pid_tgid >> 32);
	return 0;
}

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's called with on_exit argument != 0 when called from do_exit
 * function with same conditions like for acct_process described above.
 */
__attribute__((section("kprobe/disassociate_ctty"), used)) int
event_exit_disassociate_ctty(struct pt_regs *ctx)
{
	int on_exit = (int)PT_REGS_PARM1_CORE(ctx);

	if (on_exit)
		event_exit_send(ctx, get_current_pid_tgid() >> 32);
	return 0;
}
