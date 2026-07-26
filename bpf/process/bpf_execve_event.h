// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_EXECVE_EVENT_H__
#define __BPF_EXECVE_EVENT_H__

#include "data_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");

FUNC_INLINE __u32
read_args(void *ctx, struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p = &event->process;
	unsigned long start_stack, end_stack;
	unsigned long free_size, args_size;
	__u32 zero = 0, size = 0;
	struct execve_heap *heap;
	struct mm_struct *mm;
	char *args;
	long off;
	int err;

	with_errmetrics(probe_read, &mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return 0;

	with_errmetrics(probe_read, &start_stack, sizeof(start_stack),
			_(&mm->arg_start));
	with_errmetrics(probe_read, &end_stack, sizeof(start_stack), _(&mm->arg_end));

	if (!start_stack || !end_stack)
		return 0;

	/* skip first argument - binary path */
	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return 0;

	/* poor man's strlen */
	off = probe_read_str(&heap->maxpath, 4096, (char *)start_stack);
	if (off < 0)
		return 0;

	start_stack += off;

	size = p->size & 0x1ff /* 2*MAXARGLENGTH - 1*/;
	args = (char *)p + size;
#ifdef __LARGE_BPF_PROG
	event->exe.arg_start = size;
#endif

	if (args >= (char *)&event->process + BUFFER)
		return 0;

	/* Read arguments either to rest of the space in the event,
	 * or use data event to send it separatelly.
	 */
	free_size = (char *)&event->process + BUFFER - args;
	args_size = end_stack - start_stack;

	if (args_size < BUFFER && args_size < free_size) {
		if (args_size)
			args_size -= 1;
		size = args_size & 0x3ff /* BUFFER - 1 */;
		err = with_errmetrics(probe_read, args, size, (char *)start_stack);
		if (err < 0) {
			p->flags |= EVENT_ERROR_ARGS;
			size = 0;
		}
	} else {
		size = data_event_bytes(ctx, (struct data_event_desc *)args,
					(unsigned long)start_stack,
					args_size,
					(struct bpf_map_def *)&data_heap);
		if (size > 0)
			p->flags |= EVENT_DATA_ARGS;
	}
#ifdef __LARGE_BPF_PROG
	event->exe.arg_len = size;
#endif
	p->size_args = (__u16)size;
	return size;
}

#endif /* __BPF_EXECVE_EVENT_H__ */
