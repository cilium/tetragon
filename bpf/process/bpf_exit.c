// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_exit.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

/*
 * Hooking on do_task_dead kernel function, which is the last one the
 * task would execute after exiting. It's stable since v4.19, so it's
 * safe to hook for us.
 *
 * To find out if we are the last thread of execution in the task we
 * use current->signal->live counter (thanks Djalal! ;-) )
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
 *     atomic_dec_and_test(&tsk->signal->live);
 *     ...
 *     do_task_dead
 *       __schedule
 *       BUG
 *   }
 *
 * If task->signal->live == 0 we are the last thread of execution and we
 * won't race with another clone, because there's no other thread to call
 * it (current thread is in do_exit).
 */
__attribute__((section("kprobe/do_task_dead"), used)) int
event_exit(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u64 pid_tgid = get_current_pid_tgid();
	struct signal_struct *signal;
	atomic_t live;

	probe_read(&signal, sizeof(signal), _(&task->signal));
	probe_read(&live, sizeof(live), _(&signal->live));

	if (live.counter == 0)
		event_exit_send(ctx, pid_tgid >> 32);
	return 0;
}
