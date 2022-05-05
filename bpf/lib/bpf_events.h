// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

#include "hubble_msg.h"
#include "bpf_helpers.h"
#include "generic.h"

/* get_full_path flags */
#define UNRESOLVED_MOUNT_POINTS	   0x01
#define UNRESOLVED_PATH_COMPONENTS 0x02

#ifdef __LARGE_BPF_PROG
#define PROBE_CWD_READ_ITERATIONS 32
#define MAX_MOUNT_POINTS	  32
#else
#define PROBE_CWD_READ_ITERATIONS 11
#endif

/* Not sure if the following is more clear compared to
 * the previous approach but it will be more same as now
 * we use PROBE_CWD_READ_ITERATIONS in more than one places.
 */
#define M_REPEAT_1(X)  X
#define M_REPEAT_2(X)  M_REPEAT_1(X) X
#define M_REPEAT_3(X)  M_REPEAT_2(X) X
#define M_REPEAT_4(X)  M_REPEAT_3(X) X
#define M_REPEAT_5(X)  M_REPEAT_4(X) X
#define M_REPEAT_6(X)  M_REPEAT_5(X) X
#define M_REPEAT_7(X)  M_REPEAT_6(X) X
#define M_REPEAT_8(X)  M_REPEAT_7(X) X
#define M_REPEAT_9(X)  M_REPEAT_8(X) X
#define M_REPEAT_10(X) M_REPEAT_9(X) X
#define M_REPEAT_11(X) M_REPEAT_10(X) X
#define M_REPEAT_12(X) M_REPEAT_11(X) X
#define M_REPEAT_13(X) M_REPEAT_12(X) X
#define M_REPEAT_14(X) M_REPEAT_13(X) X
#define M_REPEAT_15(X) M_REPEAT_14(X) X
#define M_REPEAT_16(X) M_REPEAT_15(X) X
/* 16 should be enough in the case where we have program size limitations */
#define M_REPEAT_32(X) M_REPEAT_16(X) M_REPEAT_16(X)

#define M_EXPAND(...) __VA_ARGS__

#define M_REPEAT__(N, X) M_EXPAND(M_REPEAT_##N)(X)
#define M_REPEAT_(N, X)	 M_REPEAT__(N, X)
#define M_REPEAT(N, X)	 M_REPEAT_(M_EXPAND(N), X)

static inline __attribute__((always_inline)) int64_t
validate_arg_size(int64_t size)
{
	compiler_barrier();
	/* Kernels pre 4.15 do not track min values on '&' so we do
	 * the more explicit greather than followed by less than
	 * check to accumulate min/max bounds. Size can not be zero
	 * else older kernels will throw an error on probe_read() we
	 * require a msg_process header regardless so ensure size
	 * accounts for this at minimum.
	 */
	if (size >= BUFFER + offsetof(struct msg_process, args))
		size = BUFFER + offsetof(struct msg_process, args);
	if (size < offsetof(struct msg_process, args))
		size = offsetof(struct msg_process, args);
	compiler_barrier();
	return size;
}

static inline __attribute__((always_inline)) struct task_struct *
get_parent(struct task_struct *t)
{
	struct task_struct *task;

	probe_read(&task, sizeof(task), _(&t->parent));
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
		probe_read(&cpid, sizeof(cpid), _(&task->tgid));
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

static inline __attribute__((always_inline)) int64_t
event_copy_execve(struct msg_process *dst, struct msg_process *src)
{
	struct msg_process *esrc;
	int64_t size;

	size = validate_arg_size(src->size);
	esrc = (void *)src + size;
	compiler_barrier();
	size = validate_arg_size(esrc->size);
	compiler_barrier();
	probe_read(dst, size, esrc);
	// must be size (NOT dst->size) because size is sanitized and int64_t
	return size;
}

static inline __attribute__((always_inline)) __u32
event_find_parent_pid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);
	__u32 pid;

	if (!task)
		return 0;
	probe_read(&pid, sizeof(pid), _(&task->tgid));
	return pid;
}

static inline __attribute__((always_inline)) struct execve_map_value *
event_find_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read(&task, sizeof(task), _(&task->parent));
		if (!task)
			break;
		probe_read(&pid, sizeof(pid), _(&task->tgid));
		value = execve_map_get(pid);
		if (value && value->key.ktime != 0)
			return value;
	}
	return 0;
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
event_find_curr(__u32 *ppid, struct bpf_map_def *map, bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u32 pid = get_current_pid_tgid() >> 32;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		value = execve_map_get(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		*walked = 1;
		probe_read(&task, sizeof(task), _(&task->parent));
		if (!task)
			break;
		probe_read(&pid, sizeof(pid), _(&task->tgid));
	}
	*ppid = pid;

	if (!value && map) {
		struct execve_map_value *parent;
		int zero = 0;

		value = execve_map_get(zero);
		if (!value)
			return 0;
		parent = event_find_parent();
		if (parent)
			value->pkey = parent->pkey;
		else {
			value->pkey.ktime = 0;
			value->pkey.pid = 0;
		}
		event_minimal_curr(value);
	}
	return value;
}
#endif // _BPF_EVENTS_H
