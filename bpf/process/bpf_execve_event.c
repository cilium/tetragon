// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "errmetrics.h"
#include "bpf_mbset.h"
#include "bpf_ktime.h"
#include "environ_conf.h"

#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#ifdef __RHEL7_BPF_PROG
#define exec_ctx_struct ftrace_raw_sched_process_exec
#else
#define exec_ctx_struct trace_event_raw_sched_process_exec
#endif

#ifndef OVERRIDE_TAILCALL
int execve_rate(void *ctx);
int execve_send(struct exec_ctx_struct *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, int(void *));
} execve_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&execve_rate,
		[1] = (void *)&execve_send,
	},
};
#endif

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

#ifdef __LARGE_BPF_PROG
volatile const __u8 ENV_VARS_ENABLED;

FUNC_INLINE __u32 read_envs(void *ctx, struct msg_execve_event *event)
{
	struct msg_process *p = &event->process;
	struct mm_struct *mm = NULL;
	struct task_struct *task;
	__u32 size = 0, flags = 0;
	unsigned long free_size, envs_size;
	unsigned long env_start, env_end;
	char *envs;
	int err;

	if (!ENV_VARS_ENABLED)
		return 0;

	envs = (char *)p + p->size;
	if (envs >= (char *)&event->process + BUFFER)
		return 0;

	task = (struct task_struct *)get_current_task();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return 0;

	with_errmetrics(probe_read, &env_start, sizeof(env_start), _(&mm->env_start));
	with_errmetrics(probe_read, &env_end, sizeof(env_end), _(&mm->env_end));

	if (!env_start || !env_end)
		return 0;

	free_size = (char *)&event->process + BUFFER - envs;
	envs_size = env_end - env_start;

	if (envs_size < BUFFER && envs_size < free_size) {
		if (envs_size)
			envs_size -= 1;
		size = envs_size & 0x3ff; /* BUFFER - 1 */

		err = probe_read(envs, size, (char *)env_start);
		if (err < 0) {
			flags |= EVENT_ENVS_ERROR;
			size = 0;
		}
	} else {
		size = data_event_bytes(ctx, (struct data_event_desc *)envs,
					(unsigned long)env_start,
					envs_size,
					(struct bpf_map_def *)&data_heap);
		if (size > 0)
			flags |= EVENT_ENVS_DATA;
	}

	p->size_envs = size;
	p->flags |= flags;
	return size;
}
#else
FUNC_INLINE __u32 read_envs(void *ctx, struct msg_execve_event *event)
{
	return 0;
}
#endif

FUNC_INLINE __u32
read_path(void *ctx, struct msg_execve_event *event, void *filename)
{
	struct msg_process *p = &event->process;
	__s32 size = 0;
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
	} else if (size > 0) {
		/* remove null byte */
		size -= 1;
	}

	p->size_path = (__u16)size;
	p->flags |= flags;
	return size;
}

FUNC_INLINE __u32
read_cwd(void *ctx, struct msg_process *p)
{
	if (p->flags & EVENT_ERROR_CWD)
		return 0;
	return getcwd(p, p->size, p->pid);
}

FUNC_INLINE void
read_execve_shared_info(void *ctx, struct msg_process *p, __u64 pid)
{
	struct execve_info *info;

	info = execve_joined_info_map_get(pid);
	if (!info) {
		p->secureexec = 0;
		p->i_ino = 0;
		p->i_nlink = 0;
		return;
	}

	p->secureexec = info->secureexec;
	p->i_ino = info->i_ino;
	p->i_nlink = info->i_nlink;
	execve_joined_info_map_clear(pid);
}

__attribute__((section("tracepoint/sys_execve"), used)) int
event_execve(struct exec_ctx_struct *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	char *filename = (char *)ctx + (_(ctx->__data_loc_filename) & 0xFFFF);
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
		update_mb_task(parent);
	} else {
		event_minimal_parent(event, task);
	}

	p = &event->process;
	p->flags = EVENT_EXECVE;
	p->size_path = 0;
	p->size_args = 0;
	p->size_cwd = 0;

	/**
	 * Per thread tracking rules TID == PID :
	 *  At exec all threads other than the calling one are destroyed, so
	 *  current becomes the new thread leader since we hook late during
	 *  execve.
	 */
	p->pid = pid >> 32;
	p->tid = (__u32)pid;
	p->nspid = get_task_pid_vnr_curr();
	p->ktime = tg_get_ktime();
	p->size = offsetof(struct msg_process, args);
	p->auid = get_auid();
	read_execve_shared_info(ctx, p, pid);

	p->size += read_path(ctx, event, filename);
	p->size += read_args(ctx, event);
	p->size += read_cwd(ctx, p);
	p->size += read_envs(ctx, event);

	event->common.op = MSG_OP_EXECVE;
	event->common.ktime = p->ktime;
	event->common.size = offsetof(struct msg_execve_event, process) + p->size;

	get_current_subj_creds(&event->creds, task);
	/**
	 * Instead of showing the task owner, we want to display the effective
	 * uid that is used to calculate the privileges of current task when
	 * acting upon other objects. This allows to be compatible with the 'ps'
	 * tool that reports snapshot of current processes.
	 */
	p->uid = event->creds.euid;
	get_namespaces(&event->ns, task);
#ifndef __RHEL7_BPF_PROG
	p->flags |= __event_get_cgroup_info(task, &event->kube);
#endif

	tail_call(ctx, &execve_calls, 0);
	return 0;
}

__attribute__((section("tracepoint"), used)) int
execve_rate(void *ctx __arg_ctx)
{
	struct msg_execve_event *msg;
	__u32 zero = 0;

	msg = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!msg)
		return 0;

	if (cgroup_rate(ctx, &msg->kube, msg->common.ktime))
		tail_call(ctx, &execve_calls, 1);
	return 0;
}

/**
 * execve_send() sends the collected execve event data.
 *
 * This function is the last tail call of the execve event, its sole purpose
 * is to update the pid execve_map entry to reflect the new execve event that
 * has already been collected, then send it to the perf buffer.
 */
__attribute__((section("tracepoint"), used)) int
execve_send(struct exec_ctx_struct *ctx __arg_ctx)
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

#ifdef __LARGE_BPF_PROG
	// Reading the absolute path of the process exe for matchBinaries.
	// Historically we used the filename, a potentially relative path (maybe to
	// a symlink) coming from the execve tracepoint. For kernels not supporting
	// large BPF prog, we still use the filename.
	read_exe((struct task_struct *)get_current_task(), &event->exe);
#endif

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
		curr->flags &= ~EVENT_COMMON_FLAG_CLONE;
		/* Set EVENT_IN_INIT_TREE flag on the process if nspid=1.
		 */
		set_in_init_tree(curr, NULL);
		if (curr->flags & EVENT_IN_INIT_TREE) {
			event->process.flags |= EVENT_IN_INIT_TREE;
		}
#ifdef __NS_CHANGES_FILTER
		if (init_curr)
			memcpy(&(curr->ns), &(event->ns),
			       sizeof(struct msg_ns));
#endif
#ifdef __CAP_CHANGES_FILTER
		if (init_curr) {
			curr->caps.permitted = event->creds.caps.permitted;
			curr->caps.effective = event->creds.caps.effective;
			curr->caps.inheritable = event->creds.caps.inheritable;
		}
#endif
		/* zero out previous paths in ->bin */
		binary_reset(&curr->bin);
#ifdef __LARGE_BPF_PROG
		__u32 off, len;

		// read from proc exe stored at execve time
		if (event->exe.len <= BINARY_PATH_MAX_LEN) {
			curr->bin.path_length = with_errmetrics(probe_read, curr->bin.path, event->exe.len, event->exe.buf);
			if (curr->bin.path_length == 0)
				curr->bin.path_length = event->exe.len;
			__u64 revlen = event->exe.len;

			if (event->exe.len > STRING_POSTFIX_MAX_LENGTH - 1)
				revlen = STRING_POSTFIX_MAX_LENGTH - 1;
			with_errmetrics(probe_read, curr->bin.end, revlen, event->exe.end);
		}

		off = event->exe.arg_start;
		if (event->exe.arg_len > sizeof(curr->bin.args) - 2)
			len = sizeof(curr->bin.args) - 2;
		else
			len = event->exe.arg_len;
		with_errmetrics(probe_read, curr->bin.args, len, (char *)&event->process + off);

		// there's a null byte between each argv element, so we terminate with
		// two of them to make it possible to identify the end of the buffer
		curr->bin.args[len] = 0x00;
		curr->bin.args[len + 1] = 0x00;
#else
		char *filename = (char *)ctx + (_(ctx->__data_loc_filename) & 0xFFFF);

		curr->bin.path_length = probe_read_str(curr->bin.path, BINARY_PATH_MAX_LEN, (void *)filename);
		if (curr->bin.path_length > 1) {
			// don't include the NULL byte in the length
			curr->bin.path_length--;
		}
#endif

		update_mb_bitset(&curr->bin);
	}

	event->common.flags = 0;
	size = validate_msg_execve_size(
		sizeof(struct msg_common) + sizeof(struct msg_k8s) +
		sizeof(struct msg_execve_key) + sizeof(__u64) +
		sizeof(struct msg_cred) + sizeof(struct msg_ns) +
		sizeof(struct msg_execve_key) + p->size);
	event_output_metric(ctx, MSG_OP_EXECVE, event, size);
	return 0;
}
