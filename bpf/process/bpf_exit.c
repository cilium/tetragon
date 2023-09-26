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
__attribute__((section("kprobe/acct_collect"), used)) int
BPF_KPROBE(tg_kp_event_exit, long code, int group_dead)
{
	__u64 pid_tgid = get_current_pid_tgid();

	if (group_dead) {
		event_exit_send(ctx, pid_tgid >> 32);
	}
	return 0;
}
