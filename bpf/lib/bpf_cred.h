// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __BPF_CRED_
#define __BPF_CRED_

// NB: in some cases we want to access the capabilities via an array to simplify the BPF code, which is why we define it as a union.
struct msg_capabilities {
	union {
		struct {
			__u64 permitted;
			__u64 effective;
			__u64 inheritable;
		};
		__u64 c[3];
	};
}; // All fields aligned so no 'packed' attribute.

// indexes to access msg_capabilities's array (->c) -- should have the same order as the fields above.
enum {
	caps_permitted = 0,
	caps_effective = 1,
	caps_inheritable = 2,
};

struct msg_capability {
	__s32 cap;
	__s32 pad;
};

struct msg_user_namespace {
	__s32 level;
	__u32 uid;
	__u32 gid;
	__u32 ns_inum;
};

struct msg_cred {
	__u32 uid;
	__u32 gid;
	__u32 suid;
	__u32 sgid;
	__u32 euid;
	__u32 egid;
	__u32 fsuid;
	__u32 fsgid;
	__u32 securebits;
	__u32 pad;
	struct msg_capabilities caps;
	struct msg_user_namespace user_ns;
} __attribute__((packed));

static inline __attribute__((always_inline)) void
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
static inline __attribute__((always_inline)) void
get_current_subj_caps(struct msg_capabilities *msg, struct task_struct *task)
{
	const struct cred *cred;

	/* Get the task's subjective creds */
	probe_read(&cred, sizeof(cred), _(&task->cred));
	__get_caps(msg, cred);
}

static inline __attribute__((always_inline)) void
__get_current_uids(struct msg_cred *info, const struct cred *cred)
{
	probe_read(&info->uid, sizeof(__u32), _(&cred->uid));
	probe_read(&info->gid, sizeof(__u32), _(&cred->gid));
	probe_read(&info->euid, sizeof(__u32), _(&cred->euid));
	probe_read(&info->egid, sizeof(__u32), _(&cred->egid));
	probe_read(&info->suid, sizeof(__u32), _(&cred->suid));
	probe_read(&info->sgid, sizeof(__u32), _(&cred->sgid));
	probe_read(&info->fsuid, sizeof(__u32), _(&cred->fsuid));
	probe_read(&info->fsgid, sizeof(__u32), _(&cred->fsgid));
	probe_read(&info->securebits, sizeof(__u32), _(&cred->securebits));
	info->pad = 0;
}

static inline __attribute__((always_inline)) void
__get_current_userns(struct msg_user_namespace *info, const struct user_namespace *ns)
{
	probe_read(&info->level, sizeof(__s32), _(&ns->level));
	probe_read(&info->uid, sizeof(__u32), _(&ns->owner));
	probe_read(&info->gid, sizeof(__u32), _(&ns->group));
	probe_read(&info->ns_inum, sizeof(__u32), _(&ns->ns.inum));
}

/* get_current_subj_creds() copies uids/gids + user namespace, it still does
 * not copy capabilities.
 */
static inline __attribute__((always_inline)) void
get_current_subj_creds(struct msg_cred *info, struct task_struct *task)
{
	const struct cred *cred;
	const struct user_namespace *ns;

	/* Get the task's subjective creds */
	probe_read(&cred, sizeof(cred), _(&task->cred));
	probe_read(&ns, sizeof(ns), _(&cred->user_ns));

	__get_current_uids(info, cred);
	__get_current_userns(&info->user_ns, ns);
}

#endif
