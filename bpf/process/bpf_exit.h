/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Authors of Cilium */

#ifndef __EXIT_H__
#define __EXIT_H__

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct msg_exit);
} exit_heap_map SEC(".maps");

static inline __attribute__((always_inline)) void event_exit_send(struct sched_execve_args *ctx, __u64 current)
{
	struct execve_map_value *enter;
	__u32 pid, tgid;

	pid = current & 0xFFFFffff;
	tgid = current >> 32;

	/* We are only tracking group leaders so if tgid is not
	 * the same as the pid then this is an untracked child
	 * and we can skip the lookup/insert/delete cycle that
	 * would otherwise occur.
	 */
	if (pid != tgid)
		return;

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
		struct task_struct *task = (struct task_struct *)get_current_task();
		size_t size = sizeof(struct msg_exit);
		struct msg_exit *exit;
		int zero = 0;

		exit = map_lookup_elem(&exit_heap_map, &zero);
		if (!exit)
			return;

		exit->common.op = MSG_OP_EXIT;
		exit->common.flags = 0;
		exit->common.pad[0] = 0;
		exit->common.pad[1] = 0;
		exit->common.size = size;
		exit->common.ktime = ktime_get_ns();

		exit->current.pid = tgid;
		exit->current.pad[0] = 0;
		exit->current.pad[1] = 0;
		exit->current.pad[2] = 0;
		exit->current.pad[3] = 0;
		exit->current.ktime = enter->key.ktime;

		/* We track and report only thread leader so here tgid == tid */
		exit->info.tid = tgid;
		probe_read(&exit->info.code, sizeof(exit->info.code),
			   _(&task->exit_code));

		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, exit,
				  size);
	}
	execve_map_delete(tgid);
}

#endif /* __EXIT_H__ */
