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

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section("kprobe/wake_up_new_task"), used)) int
BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
	struct execve_map_value *curr, *parent;
	struct msg_clone_event msg;
	u64 msg_size = sizeof(struct msg_clone_event);
	struct msg_k8s kube;
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
	curr->key.ktime = ktime_get_ns();
	curr->nspid = get_task_pid_vnr_by_task(task);
	memcpy(&curr->bin, &parent->bin, sizeof(curr->bin));
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
	msg.common.op = MSG_OP_CLONE;
	msg.common.size = msg_size;
	msg.common.ktime = curr->key.ktime;
	msg.parent = curr->pkey;
	msg.tgid = curr->key.pid;
	/* Per thread tracking rules TID == PID :
	 *  Since we generate one event per thread group, then when this task
	 *  wakes up it will be the only one in the thread group, and it is
	 *  the leader. Ensure to pass TID to user space.
	 */
	msg.tid = BPF_CORE_READ(task, pid);
	msg.ktime = curr->key.ktime;
	msg.nspid = curr->nspid;
	msg.flags = curr->flags;

	__event_get_cgroup_info(task, &kube);

	if (cgroup_rate(ctx, &kube, msg.ktime)) {
		perf_event_output_metric(ctx, MSG_OP_CLONE, &tcpmon_map,
					 BPF_F_CURRENT_CPU, &msg, msg_size);
	}

	return 0;
}
