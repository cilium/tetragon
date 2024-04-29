// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _BPF_TASK_H
#define _BPF_TASK_H

#include "bpf_event.h"
#include "bpf_helpers.h"
#include "generic.h"
#include "bpf_tracing.h"

/* __d_path_local flags */
// #define UNRESOLVED_MOUNT_POINTS	   0x01 // (deprecated)
// this error is returned by __d_path_local in the following cases:
// - the path walk did not conclude (too many dentry)
// - the path was too long to fit in the buffer
#define UNRESOLVED_PATH_COMPONENTS 0x02

#ifdef __LARGE_BPF_PROG
#define PROBE_CWD_READ_ITERATIONS 128
#else
#define PROBE_CWD_READ_ITERATIONS 11
#endif

static inline __attribute__((always_inline)) struct task_struct *
get_parent(struct task_struct *t)
{
	struct task_struct *task;

	/* Read the real parent */
	probe_read_kernel(&task, sizeof(task), _(&t->real_parent));
	if (!task)
		return 0;
	return task;
}

static inline __attribute__((always_inline)) struct task_struct *
get_task_from_pid(__u32 pid)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 cpid = 0;
	int i;

#define TASK_PID_LOOP 20
#pragma unroll
	for (i = 0; i < TASK_PID_LOOP; i++) {
		if (!task) {
			i = TASK_PID_LOOP;
			continue;
		}
		probe_read_kernel(&cpid, sizeof(cpid), _(&task->tgid));
		if (cpid == pid) {
			i = TASK_PID_LOOP;
			continue;
		}
		task = get_parent(task);
	}
	if (cpid != pid)
		return 0;
	return task;
}

static inline __attribute__((always_inline)) __u32 get_task_pid_vnr(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	int thread_pid_exists;
	unsigned int level;
	struct upid upid;
	struct pid *pid;
	int upid_sz;

	thread_pid_exists = bpf_core_field_exists(task->thread_pid);
	if (thread_pid_exists) {
		probe_read_kernel(&pid, sizeof(pid), _(&task->thread_pid));
		if (!pid)
			return 0;
	} else {
		struct pid_link link;
		int link_sz = bpf_core_field_size(task->pids);

		/* 4.14 verifier did not prune this branch even though we
		 * have the if (0) above after BTF exists check. So it will
		 * try to run this probe_read and throw an error. So lets
		 * sanitize it for the verifier.
		 */
		if (!thread_pid_exists)
			link_sz =
				24; // voodoo magic, hard-code 24 to init stack
		probe_read_kernel(&link, link_sz,
				  (void *)_(&task->pids) + (PIDTYPE_PID * link_sz));
		pid = link.pid;
	}
	upid_sz = bpf_core_field_size(pid->numbers[0]);
	probe_read_kernel(&level, sizeof(level), _(&pid->level));
	if (level < 1)
		return 0;
	probe_read_kernel(&upid, upid_sz,
			  (void *)_(&pid->numbers) + (level * upid_sz));
	return upid.nr;
}

static inline __attribute__((always_inline)) __u32
event_find_parent_pid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);
	__u32 pid;

	if (!task)
		return 0;
	probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
	return pid;
}

static inline __attribute__((always_inline)) struct execve_map_value *
__event_find_parent(struct task_struct *task)
{
	__u32 pid;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read_kernel(&task, sizeof(task), _(&task->real_parent));
		if (!task)
			break;
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			return value;
	}
	return 0;
}

static inline __attribute__((always_inline)) struct execve_map_value *
event_find_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __event_find_parent(task);
}

static inline __attribute__((always_inline)) void
event_minimal_parent(struct msg_execve_event *event, struct task_struct *task)
{
	event->parent.pid = event_find_parent_pid(task);
	event->parent.ktime = 0;
	event->parent_flags = EVENT_MISS;
}

static inline __attribute__((always_inline)) void
event_minimal_curr(struct execve_map_value *event)
{
	event->key.pid = (get_current_pid_tgid() >> 32);
	event->key.ktime = 0; // should we insert a time?
	event->flags = EVENT_MISS;
}

static inline __attribute__((always_inline)) struct execve_map_value *
event_find_curr(__u32 *ppid, bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct execve_map_value *value = 0;
	int i;
	__u32 pid;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		*walked = 1;
		probe_read_kernel(&task, sizeof(task), _(&task->real_parent));
		if (!task)
			break;
	}
	*ppid = pid;
	return value;
}
#endif // _BPF_TASK_H
