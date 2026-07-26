// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_execve_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "errmetrics.h"
#include "bpf_mbset.h"
#include "bpf_ktime.h"
#include "environ_conf.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#ifndef OVERRIDE_TAILCALL
int execve_rate(void *ctx);
int execve_send(struct bpf_raw_tracepoint_args *ctx);

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

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve_event_init(ctx, event);

	tail_call(ctx, &execve_calls, 0);
	return 0;
}

__attribute__((section("raw_tracepoint"), used)) int
execve_rate(void *ctx __arg_ctx)
{
#ifndef __RHEL7_BPF_PROG
	struct task_struct *task = (struct task_struct *)get_current_task();
#endif
	struct msg_execve_event *msg;
	__u32 zero = 0;

	msg = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!msg)
		return 0;

#ifndef __RHEL7_BPF_PROG
	msg->process.flags |= __event_get_cgroup_info(task, &msg->kube);
#endif

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
__attribute__((section("raw_tracepoint"), used)) int
execve_send(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	struct linux_binprm *bprm __maybe_unused = (struct linux_binprm *)ctx->args[2];
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

		update_parents_map(event, curr);

		/* zero out previous paths in ->bin */
		binary_reset(&curr->bin);
#ifdef __LARGE_BPF_PROG
		__u32 off, len;

		// read from proc exe stored at execve time
		copy_exe_to_bin(&event->exe, &curr->bin);

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
		struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
		char *filename;

		probe_read(&filename, sizeof(filename), _(&bprm->filename));
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
