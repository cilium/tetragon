// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _BPF_PROCESS_EVENT__
#define _BPF_PROCESS_EVENT__

#include "bpf_helpers.h"

#include "bpf_cgroup.h"
#include "bpf_cred.h"
#include "bpf_d_path.h"
#include "bpf_tracing.h"
#include "bpf_ktime.h"

#include "cgroup/cgtracker.h"

#define MATCH_BINARIES_PATH_MAX_LENGTH 256

FUNC_INLINE __u64 __get_auid(struct task_struct *t)
{
	struct task_struct___local *task = (struct task_struct___local *)t;

	// u64 to convince compiler to do 64bit loads early kernels do not
	// support 32bit loads from stack, e.g. r1 = *(u32 *)(r10 -8).
	__u64 auid = 0;

	if (!task)
		return auid;

	if (bpf_core_field_exists(task->loginuid)) {
		probe_read(&auid, sizeof(auid), _(&task->loginuid.val));
	} else {
		struct audit_task_info *audit;

		if (bpf_core_field_exists(task->audit)) {
			probe_read(&audit, sizeof(audit), _(&task->audit));
			if (audit) {
				probe_read(&auid, sizeof(__u32),
					   _(&audit->loginuid));
			}
		}
	}

	return auid;
}

FUNC_INLINE __u32 get_auid(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __get_auid(task);
}

FUNC_INLINE __u32
getcwd(struct msg_process *curr, __u32 offset, __u32 proc_pid)
{
	struct task_struct *task = get_task_from_pid(proc_pid);
	struct fs_struct *fs;
	int flags = 0, size;
	char *buffer;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		curr->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	buffer = d_path_local(_(&fs->pwd), &size, &flags);
	if (!buffer)
		return 0;

	asm volatile("%[offset] &= 0x3ff;\n"
		     : [offset] "+r"(offset));
	asm volatile("%[size] &= 0xfff;\n"
		     : [size] "+r"(size));
	probe_read((char *)curr + offset, size, buffer);

	// Unfortunate special case for '/' where nothing was added we need
	// to truncate with '\n' for parser.
	if (size == 0)
		curr->flags |= EVENT_ROOT_CWD;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		curr->flags |= EVENT_ERROR_PATH_COMPONENTS;
	curr->flags = curr->flags & ~(EVENT_NEEDS_CWD | EVENT_ERROR_CWD);
	curr->size_cwd = (__u16)size;
	return (__u32)size;
}

FUNC_INLINE void event_set_clone(struct msg_process *pid)
{
	pid->flags |= EVENT_CLONE;
}

FUNC_INLINE void
__get_caps(struct msg_capabilities *msg, const struct cred *cred)
{
	probe_read(&msg->effective, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&msg->inheritable, sizeof(__u64), _(&cred->cap_inheritable));
	probe_read(&msg->permitted, sizeof(__u64), _(&cred->cap_permitted));
}

/* @get_current_subj_caps:
 * Retrieve current task capabilities from the subjective credentials and
 * return it into @msg.
 *
 * Use this function to report current task capabilities that will be used to
 * calculate the security access when acting upon other objects.
 *
 * Special care must be taken to ensure that @task is "current".
 *
 * From: https://github.com/torvalds/linux/blob/v6.0/include/linux/cred.h#L88
 * "
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 * "
 */
FUNC_INLINE void
get_current_subj_caps(struct msg_capabilities *msg, struct task_struct *task)
{
	const struct cred *cred;

	/* Get the task's subjective creds */
	probe_read(&cred, sizeof(cred), _(&task->cred));
	__get_caps(msg, cred);
}

FUNC_INLINE void
get_current_subj_creds(struct msg_cred *info, struct task_struct *task)
{
	const struct cred *cred;

	/* Get the task's subjective creds */
	probe_read(&cred, sizeof(cred), _(&task->cred));

	probe_read(&info->uid, sizeof(__u32), _(&cred->uid));
	probe_read(&info->gid, sizeof(__u32), _(&cred->gid));
	probe_read(&info->euid, sizeof(__u32), _(&cred->euid));
	probe_read(&info->egid, sizeof(__u32), _(&cred->egid));
	probe_read(&info->suid, sizeof(__u32), _(&cred->suid));
	probe_read(&info->sgid, sizeof(__u32), _(&cred->sgid));
	probe_read(&info->fsuid, sizeof(__u32), _(&cred->fsuid));
	probe_read(&info->fsgid, sizeof(__u32), _(&cred->fsgid));
	probe_read(&info->securebits, sizeof(__u32), _(&cred->securebits));

	/* Get capabilities */
	__get_caps(&info->caps, cred);
}

FUNC_INLINE void
get_namespaces(struct msg_ns *msg, struct task_struct *task)
{
	struct nsproxy *nsproxy;
	struct nsproxy nsp;

	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	probe_read(&nsp, sizeof(nsp), _(nsproxy));

	if (bpf_core_field_exists(nsproxy->uts_ns->ns)) {
		probe_read(&msg->uts_inum, sizeof(msg->uts_inum),
			   _(&nsp.uts_ns->ns.inum));
	} else {
		struct uts_namespace___rhel7 *ns = (struct uts_namespace___rhel7 *)_(nsp.uts_ns);

		probe_read(&msg->uts_inum, sizeof(msg->uts_inum),
			   _(&ns->proc_inum));
	}

	if (bpf_core_field_exists(nsproxy->ipc_ns->ns)) {
		probe_read(&msg->ipc_inum, sizeof(msg->ipc_inum),
			   _(&nsp.ipc_ns->ns.inum));
	} else {
		struct ipc_namespace___rhel7 *ns = (struct ipc_namespace___rhel7 *)_(nsp.ipc_ns);

		probe_read(&msg->ipc_inum, sizeof(msg->ipc_inum),
			   _(&ns->proc_inum));
	}

	if (bpf_core_field_exists(nsproxy->mnt_ns->ns)) {
		probe_read(&msg->mnt_inum, sizeof(msg->mnt_inum),
			   _(&nsp.mnt_ns->ns.inum));
	} else {
		struct mnt_namespace___rhel7 *ns = (struct mnt_namespace___rhel7 *)_(nsp.mnt_ns);

		probe_read(&msg->ipc_inum, sizeof(msg->ipc_inum),
			   _(&ns->proc_inum));
	}

	// TODO rhel7 pid namespace support
	if (bpf_core_field_exists(task->thread_pid)) {
		struct pid *p = 0;

		probe_read(&p, sizeof(p), _(&task->thread_pid));
		if (p) {
			int level = 0;
			struct upid up;

			probe_read(&level, sizeof(level), _(&p->level));
			probe_read(&up, sizeof(up), _(&p->numbers[level]));
			probe_read(&msg->pid_inum, sizeof(msg->pid_inum),
				   _(&up.ns->ns.inum));
		} else
			msg->pid_inum = 0;
	}

	if (bpf_core_field_exists(nsproxy->pid_ns_for_children)) {
		probe_read(&msg->pid_for_children_inum,
			   sizeof(msg->pid_for_children_inum),
			   _(&nsp.pid_ns_for_children->ns.inum));
	} else {
		msg->pid_for_children_inum = 0;
	}

	if (bpf_core_field_exists(nsproxy->net_ns->ns)) {
		probe_read(&msg->net_inum, sizeof(msg->net_inum),
			   _(&nsp.net_ns->ns.inum));
	} else {
		struct net___rhel7 *ns = (struct net___rhel7 *)_(nsp.net_ns);

		probe_read(&msg->net_inum, sizeof(msg->net_inum),
			   _(&ns->proc_inum));
	}

	// this also includes time_ns_for_children
	if (bpf_core_field_exists(nsproxy->time_ns)) {
		probe_read(&msg->time_inum, sizeof(msg->time_inum),
			   _(&nsp.time_ns->ns.inum));
		probe_read(&msg->time_for_children_inum,
			   sizeof(msg->time_for_children_inum),
			   _(&nsp.time_ns_for_children->ns.inum));
	}

	if (bpf_core_field_exists(nsproxy->cgroup_ns)) {
		probe_read(&msg->cgroup_inum, sizeof(msg->cgroup_inum),
			   _(&nsp.cgroup_ns->ns.inum));
	} else {
		msg->cgroup_inum = 0;
	}

	{
		struct mm_struct *mm = NULL;
		struct user_namespace *user_ns;

		if (bpf_core_field_exists(mm->user_ns)) {
			probe_read(&mm, sizeof(mm), _(&task->mm));
			probe_read(&user_ns, sizeof(user_ns), _(&mm->user_ns));
			probe_read(&msg->user_inum, sizeof(msg->user_inum),
				   _(&user_ns->ns.inum));
		} else {
			msg->user_inum = 0;
		}
	}
}

/* Gather current task cgroup name */
FUNC_INLINE __u32
__event_get_current_cgroup_name(struct cgroup *cgrp, struct msg_k8s *kube)
{
	const char *name;

	name = get_cgroup_name(cgrp);
	if (name)
		probe_read_str(kube->docker_id, KN_NAME_LENGTH, name);

	return name ? 0 : EVENT_ERROR_CGROUP_NAME;
}

/**
 * __event_get_cgroup_info() Collect cgroup info from current task.
 * @task: must be current task.
 * @msg: the msg_execve_event where to store collected information.
 *
 * Checks the tg_conf_map BPF map for cgroup and runtime configurations then
 * collects cgroup information from current task. This allows to operate on
 * different machines and workflows.
 */
FUNC_INLINE __u32
__event_get_cgroup_info(struct task_struct *task, struct msg_k8s *kube)
{
	__u64 cgrpfs_magic = 0;
	int zero = 0, subsys_idx = 0;
	struct cgroup *cgrp;
	struct tetragon_conf *conf;
	__u32 flags = 0;

	/* Clear cgroup info at the beginning, so if we return early we do not pass previous data */
	memset(kube, 0, sizeof(struct msg_k8s));

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf) {
		/* Select which cgroup version */
		cgrpfs_magic = conf->cgrp_fs_magic;
		subsys_idx = conf->tg_cgrpv1_subsys_idx;
	}

	cgrp = get_task_cgroup(task, cgrpfs_magic, subsys_idx, &flags);
	if (!cgrp)
		return 0;

	/* Collect event cgroup ID */
	kube->cgrpid = __tg_get_current_cgroup_id(cgrp, cgrpfs_magic);
	if (kube->cgrpid)
		kube->cgrp_tracker_id = cgrp_get_tracker_id(kube->cgrpid);
	else
		flags |= EVENT_ERROR_CGROUP_ID;

	/* Get the cgroup name of this event. */
	flags |= __event_get_current_cgroup_name(cgrp, kube);
	return flags;
}

FUNC_INLINE void
set_in_init_tree(struct execve_map_value *curr, struct execve_map_value *parent)
{
	if (parent && parent->flags & EVENT_IN_INIT_TREE) {
		curr->flags |= EVENT_IN_INIT_TREE;
		DEBUG("%s: parent in init tree", __func__);
		return;
	}

	if (curr->nspid == 1) {
		curr->flags |= EVENT_IN_INIT_TREE;
		DEBUG("%s: nspid=1", __func__);
	}
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE struct execve_map_value *
event_find_curr_probe(struct msg_generic_kprobe *msg)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct execve_map_value *curr;

	curr = &msg->curr;
	curr->key.pid = BPF_CORE_READ(task, tgid);
	curr->key.ktime = tg_get_ktime();
	curr->nspid = get_task_pid_vnr_by_task(task);

	get_current_subj_caps(&curr->caps, task);
	get_namespaces(&curr->ns, task);
	set_in_init_tree(curr, NULL);

	read_exe((struct task_struct *)get_current_task(), &msg->exe);
	return curr;
}
#else
FUNC_INLINE struct execve_map_value *
event_find_curr_probe(struct msg_generic_kprobe *msg)
{
	return NULL;
}
#endif
#endif
