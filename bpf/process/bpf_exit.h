/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __EXIT_H__
#define __EXIT_H__

#include "vmlinux.h"
#include "api.h"

#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_rate.h"
#include "process.h"
#include "bpf_process_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct msg_exit);
} exit_heap_map SEC(".maps");

static inline __attribute__((always_inline)) void event_exit_send(void *ctx, __u32 tgid)
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
		struct task_struct *task = (struct task_struct *)get_current_task();
		size_t size = sizeof(struct msg_exit);
		struct msg_exit *exit;
		struct msg_k8s kube;
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

		/**
		 * Per thread tracking rules TID == PID :
		 *  We want the exit event to match the exec one, and since during exec
		 *  we report the thread group leader, do same here as we read the exec
		 *  entry from the execve_map anyway and explicitly set it to the to tgid.
		 */
		exit->info.tid = tgid;
		probe_read(&exit->info.code, sizeof(exit->info.code),
			   _(&task->exit_code));

		__event_get_cgroup_info(task, &kube);

		if (cgroup_rate(kube.cgrpid, exit->common.ktime)) {
			perf_event_output_metric(ctx, MSG_OP_EXIT, &tcpmon_map,
						 BPF_F_CURRENT_CPU, exit, size);
		}
	}
	execve_map_delete(tgid);
}

#endif /* __EXIT_H__ */
