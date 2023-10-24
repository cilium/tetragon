// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

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
	unsigned long free_size, args_size;
	__u32 zero = 0, size = 0;
	struct execve_heap *heap;
	struct mm_struct *mm;
	char *args;
	long off;
	int err;

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

	size = p->size & 0x1ff /* 2*MAXARGLENGTH - 1*/;
	args = (char *)p + size;

	if (args >= (char *)&event->process + BUFFER)
		return 0;

	/* Read arguments either to rest of the space in the event,
	 * or use data event to send it separatelly.
	 */
	free_size = (char *)&event->process + BUFFER - args;
	args_size = end_stack - start_stack;

	if (args_size < BUFFER && args_size < free_size) {
		size = args_size & 0x3ff /* BUFFER - 1 */;
		err = probe_read(args, size, (char *)start_stack);
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
	return size;
}

static inline __attribute__((always_inline)) __u32
read_path(void *ctx, struct msg_execve_event *event, void *filename)
{
	struct msg_process *p = &event->process;
	__u32 size = 0;
	__u32 flags = 0;
	char *earg;

	earg = (void *)p + offsetof(struct msg_process, args);

	size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size == MAXARGLENGTH - 1) {
		size = data_event_str(ctx, (struct data_event_desc *)earg,
				      (unsigned long)filename,
				      (struct bpf_map_def *)&data_heap);
		if (size == 0)
			flags |= EVENT_ERROR_FILENAME;
		else
			flags |= EVENT_DATA_FILENAME;
	}

	p->flags |= flags;
	return size;
}

static inline __attribute__((always_inline)) __u32
read_cwd(void *ctx, struct msg_process *p)
{
	if (p->flags & EVENT_ERROR_CWD)
		return 0;
	return getcwd(p, p->size, p->pid);
}

static inline __attribute__((always_inline)) __u32
binary_filter(void *ctx, struct msg_execve_event *event, void *filename)
{
	struct msg_process *p = &event->process;
	struct execve_heap *heap;
	uint32_t *value;
	__u32 zero = 0;

	// skip binaries check for long (> 255) filenames for now
	if (p->flags & EVENT_DATA_FILENAME)
		return 0;

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return 0;

	memset(heap->pathname, 0, PATHNAME_SIZE);
	probe_read_str(heap->pathname, PATHNAME_SIZE, filename);
	value = map_lookup_elem(&names_map, heap->pathname);
	return value ? *value : 0;
}

static inline __attribute__((always_inline)) __u32
read_execve_shared_info(void *ctx, __u64 pid)
{
	__u32 secureexec = 0;
	struct execve_info *info;

	info = execve_joined_info_map_get(pid);
	if (info) {
		secureexec = info->secureexec;
		execve_joined_info_map_clear(pid);
	}
	return secureexec;
}

__attribute__((section("tracepoint/sys_execve"), used)) int
event_execve(struct sched_execve_args *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	char *filename = (char *)ctx + (ctx->filename & 0xFFFF);
	struct msg_execve_event *event;
	struct execve_map_value *parent;
	struct msg_process *p;
	__u32 zero = 0;
	__u64 pid;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	pid = get_current_pid_tgid();
	parent = event_find_parent();
	if (parent) {
		event->parent = parent->key;
	} else {
		event_minimal_parent(event, task);
	}

	p = &event->process;
	p->flags = EVENT_EXECVE;
	/**
	 * Per thread tracking rules TID == PID :
	 *  At exec all threads other than the calling one are destroyed, so
	 *  current becomes the new thread leader since we hook late during
	 *  execve.
	 */
	p->pid = pid >> 32;
	p->tid = (__u32)pid;
	p->secureexec = read_execve_shared_info(ctx, pid);
	p->nspid = get_task_pid_vnr();
	p->ktime = ktime_get_ns();
	p->size = offsetof(struct msg_process, args);
	p->auid = get_auid();
	p->uid = get_current_uid_gid();

	p->size += read_path(ctx, event, filename);
	p->size += read_args(ctx, event);
	p->size += read_cwd(ctx, p);

	event->common.op = MSG_OP_EXECVE;
	event->common.ktime = p->ktime;
	event->common.size = offsetof(struct msg_execve_event, process) + p->size;

	event->binary = binary_filter(ctx, event, filename);

	BPF_CORE_READ_INTO(&event->kube.net_ns, task, nsproxy, net_ns, ns.inum);

	// At this time objective and subjective creds are same
	get_current_subj_caps(&event->caps, task);
	get_current_subj_creds_uids(&event->creds, task);
	get_namespaces(&event->ns, task);
	__event_get_cgroup_info(task, event);

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
		sizeof(struct msg_capabilities) +
		sizeof(struct msg_cred_minimal) + sizeof(struct msg_ns) +
		sizeof(struct msg_execve_key) + p->size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 0;
}
