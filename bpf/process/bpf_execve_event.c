// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} execve_calls SEC(".maps");

#include "data_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");

static inline __attribute__((always_inline)) __u32
read_args(void *ctx, struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p = &event->process;
	unsigned long start_stack, end_stack;
	__u32 zero = 0, total = 0, size;
	struct execve_heap *heap;
	struct mm_struct *mm;
	char *args;
	long off;

	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return 0;

	probe_read(&start_stack, sizeof(start_stack),
		   _(&mm->arg_start));
	probe_read(&end_stack, sizeof(start_stack), _(&mm->arg_end));

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

	args = (char *)p + p->size;

	if (args >= (char *)&event->process + BUFFER)
		return 0;

	size = data_event_bytes(ctx, (struct data_event_desc *)args,
				(unsigned long)start_stack,
				end_stack - start_stack,
				(struct bpf_map_def *)&data_heap);
	if (size < 0)
		return 0;
	p->flags |= EVENT_DATA_ARGS;
	total += size;
	return total;
}

static inline __attribute__((always_inline)) uint32_t
event_filename_builder(void *ctx, struct msg_process *p, __u64 curr_pid, __u32 flags, void *filename)
{
	struct execve_heap *heap;
	int64_t size = 0;
	__u32 zero = 0;
	uint32_t *value;
	char *earg;

	/* This is a bit parnoid but was previously having trouble on
	 * 4.14 kernels tracking offset of curr through filename_builder
	 * resulting in a a verifier error. We can optimize this a bit
	 * later perhaps and push as an argument.
	 */
	earg = (void *)p + offsetof(struct msg_process, args);

	size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size == MAXARGLENGTH - 1) {
		size = data_event_str(ctx, (struct data_event_desc *)earg,
				      (unsigned long)filename,
				      (struct bpf_map_def *)&data_heap);
		if (size < 0) {
			flags |= EVENT_ERROR_FILENAME;
			size = 0;
		} else {
			flags |= EVENT_DATA_FILENAME;
		}
	}

	p->flags = flags;
	/* Send the TGID and TID, as during an execve all threads other
	 * than the calling thread are destroyed, but since we hook late
	 * during the execve then the calling thread at the hook time is
	 * already the new thread group leader.
	 */
	p->pid = curr_pid >> 32;
	p->tid = (__u32)curr_pid;
	p->pad = 0;
	p->nspid = get_task_pid_vnr();
	p->ktime = ktime_get_ns();
	p->size = size + offsetof(struct msg_process, args);

	// skip binaries check for long (> 255) filenames for now
	if (flags & EVENT_DATA_FILENAME)
		return 0;

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return 0;

	memset(heap->pathname, 0, PATHNAME_SIZE);
	probe_read_str(heap->pathname, size, filename);
	value = map_lookup_elem(&names_map, heap->pathname);
	if (value)
		return *value;
	return 0;
}

__attribute__((section("tracepoint/sys_execve"), used)) int
event_execve(struct sched_execve_args *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_execve_event *event;
	struct execve_map_value *parent;
	struct msg_process *p;
	bool walker = 0;
	__u32 zero = 0;
	__u64 pid;
	unsigned short fileoff;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	/*
	 * The event we allocate above includes uninitiated data, which is
	 * zeroed out or initialized in __event_get_task_info. If code
	 * changes so that we return before __event_get_task_info is called,
	 * ensure that:
	 *  1. The necessary fields are zeroed out or properly initialized.
	 *  2. Set the event->process.flags to properly reflect errors.
	 */

	pid = get_current_pid_tgid();
	parent = event_find_parent();
	if (parent) {
		event->parent = parent->key;
	} else {
		event_minimal_parent(event, task);
	}

	p = &event->process;
	p->auid = get_auid();

	fileoff = ctx->filename & 0xFFFF;
	event->binary = event_filename_builder(ctx, p, pid, EVENT_EXECVE, (char *)ctx + fileoff);

	/* We use flags in asm to indicate overflow */
	compiler_barrier();
	p->size += read_args(ctx, event);

	compiler_barrier();
	__event_get_task_info(event, MSG_OP_EXECVE, walker, true);

	tail_call(ctx, &execve_calls, 0);
	return 0;
}

/**
 * execve_send() sends the collected execve event data.
 *
 * This function is the last tail call of the execve event, its sole purpose
 * is to update the pid execve_map entry to reflect the new execve event that
 * has already been collected, then send it to the perf buffer.
 */
__attribute__((section("tracepoint/0"), used)) int
execve_send(struct sched_execve_args *ctx)
{
	struct msg_execve_event *event;
	struct execve_map_value *curr;
	struct msg_process *p;
	__u32 zero = 0;
	uint64_t size;
	__u32 pid;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
	bool init_curr = 0;
#endif

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	p = &event->process;

	pid = (get_current_pid_tgid() >> 32);

	curr = execve_map_get_noinit(pid);
	if (curr) {
		event->cleanup_key = curr->key;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
		/* if this exec event preceds a clone, initialize  capabilities
		 * and namespaces as well.
		 */
		if (curr->flags == EVENT_COMMON_FLAG_CLONE)
			init_curr = 1;
#endif
		curr->key.pid = p->pid;
		curr->key.ktime = p->ktime;
		curr->nspid = p->nspid;
		curr->pkey = event->parent;
		if (curr->flags & EVENT_COMMON_FLAG_CLONE) {
			event_set_clone(p);
		}
		curr->flags = 0;
		curr->binary = event->binary;
#ifdef __NS_CHANGES_FILTER
		if (init_curr)
			memcpy(&(curr->ns), &(event->ns),
			       sizeof(struct msg_ns));
#endif
#ifdef __CAP_CHANGES_FILTER
		if (init_curr) {
			curr->caps.permitted = event->caps.permitted;
			curr->caps.effective = event->caps.effective;
			curr->caps.inheritable = event->caps.inheritable;
		}
#endif
	}

	event->common.flags = 0;
	size = validate_msg_execve_size(
		sizeof(struct msg_common) + sizeof(struct msg_k8s) +
		sizeof(struct msg_execve_key) + sizeof(__u64) +
		sizeof(struct msg_capabilities) + sizeof(struct msg_ns) +
		sizeof(struct msg_execve_key) + p->size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 0;
}
