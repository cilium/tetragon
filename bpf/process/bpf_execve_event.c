// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";

__attribute__((section(("tracepoint/sys_execve")), used)) int
event_execve(struct sched_execve_args *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_execve_event *event;
	struct execve_map_value *curr, *parent;
	struct msg_process *execve;
	uint32_t binary = 0;
	bool walker = 0;
	__u32 zero = 0;
	uint64_t size;
	__u32 pid;
	unsigned short fileoff;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
	bool init_curr = 0;
#endif

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;
	pid = (get_current_pid_tgid() >> 32);
	parent = event_find_parent();
	if (parent) {
		event->parent = parent->key;
		binary = parent->binary;
	} else {
		event_minimal_parent(event, task);
	}

	execve = &event->process;
	fileoff = ctx->filename & 0xFFFF;
	binary = event_filename_builder(execve, pid, EVENT_EXECVE, binary,
					(char *)ctx + fileoff);
	event_args_builder(event);
	compiler_barrier();
	__event_get_task_info(event, MSG_OP_EXECVE, walker, true);

	curr = execve_map_get(pid);
	if (curr) {
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
		/* if this exec event preceds a clone, initialize  capabilities
		 * and namespaces as well.
		 */
		if (curr->flags == EVENT_COMMON_FLAG_CLONE)
			init_curr = 1;
#endif
		curr->key.pid = execve->pid;
		curr->key.ktime = execve->ktime;
		curr->nspid = execve->nspid;
		curr->pkey = event->parent;
		if (curr->flags & EVENT_COMMON_FLAG_CLONE) {
			event_set_clone(execve);
		}
		curr->flags = 0;
		curr->binary = binary;
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
		execve->size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 0;
}
