// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_cgroup.h"
#include "bpf_task.h"
#include "environ_conf.h"
#include "bpf_process_event.h"
#include "process.h"
#include "bpf_rate.h"
#include "bpf_ktime.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

FUNC_INLINE void
event_clone_fill(struct msg_clone_event *event, struct execve_map_value *curr,
		 struct task_struct *task)
{
	event->common.op = MSG_OP_CLONE;
	event->common.flags = 0;
	event->common.pad[0] = 0;
	event->common.pad[1] = 0;
	event->common.size = sizeof(*event);
	event->common.ktime = curr->key.ktime;
	event->parent = curr->pkey;
	event->tgid = curr->key.pid;
	/* Per thread tracking rules TID == PID :
	 *  Since we generate one event per thread group, then when this task
	 *  wakes up it will be the only one in the thread group, and it is
	 *  the leader. Ensure to pass TID to user space.
	 */
	event->tid = BPF_CORE_READ(task, pid);
	event->ktime = curr->key.ktime;
	event->nspid = curr->nspid;
	event->flags = curr->flags;
}

#ifndef __RHEL7_BPF_PROG
FUNC_INLINE bool
event_clone_rate_check(void *ctx, struct task_struct *task, __u64 ktime)
{
	struct msg_k8s kube;

	if (__event_get_cgroup_info(task, &kube))
		errmetrics(ENOENT);

	return cgroup_rate(ctx, &kube, ktime);
}
#endif

#ifdef __V511_BPF_PROG
FUNC_INLINE int
rb_clone_output(void *ctx, struct execve_map_value *curr, struct task_struct *task)
{
	struct msg_clone_event *event;

	event = event_ringbuf_reserve(MSG_OP_CLONE, sizeof(struct msg_clone_event));
	if (!event)
		return 0;

	event_clone_fill(event, curr, task);

	if (!event_clone_rate_check(ctx, task, event->common.ktime)) {
		ringbuf_discard(event, 0);
		return 0;
	}
	ringbuf_submit(event, 0);
	return 0;
}
#endif

__attribute__((section("kprobe/wake_up_new_task"), used)) int
BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
	struct execve_map_value *curr, *parent;
	struct msg_clone_event msg;
	u64 msg_size = sizeof(struct msg_clone_event);
	u32 tgid = 0;

	if (!task)
		return 0;

	tgid = BPF_CORE_READ(task, tgid);

	/* Do not try to create any msg or calling execve_map_get
	 * (that will add a new process in the execve_map) if we
	 * cannot find it's parent in the execve_map.
	 */
	parent = __event_find_parent(task);
	if (!parent)
		return 0;

	curr = execve_map_get(tgid);
	if (!curr)
		return 0;

	/* Generate an EVENT_COMMON_FLAG_CLONE event once per process,
	 * that is, thread group.
	 */
	if (curr->key.ktime != 0)
		return 0;

	/* Setup the execve_map entry. */
	curr->flags = EVENT_COMMON_FLAG_CLONE;
	curr->key.pid = tgid;
	curr->key.ktime = tg_get_ktime();
	curr->nspid = get_task_pid_vnr_by_task(task);
	__bpf_memcpy_builtin(&curr->bin, &parent->bin, sizeof(curr->bin));
	__bpf_memcpy_builtin(&curr->args, &parent->args, sizeof(curr->args));
	curr->pkey = parent->key;

	/* Store the thread leader capabilities so we can check later
	 * before the execve hook point if they changed or not.
	 * This needs to be converted later to credentials.
	 */
	get_current_subj_caps(&curr->caps, task);

	/* Store the thread leader namespaces so we can check later
	 * before the execve hook point if they changed or not.
	 */
	get_namespaces(&curr->ns, task);

	/* Set EVENT_IN_INIT_TREE flag on the process if its parent is in a
	 * container's init tree or if it has nspid=1.
	 */
	set_in_init_tree(curr, parent);

	/* Setup the msg_clone_event and sent to the user. */
#ifdef __V511_BPF_PROG
	if (!CONFIG(USE_PERF_RING_BUF))
		return rb_clone_output(ctx, curr, task);
#endif

	event_clone_fill(&msg, curr, task);

#ifndef __RHEL7_BPF_PROG
	if (event_clone_rate_check(ctx, task, msg.ktime))
#endif
		event_output_metric(ctx, MSG_OP_CLONE, &msg, msg_size);

	return 0;
}
