// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef _BPF_PROCESS_EVENT__
#define _BPF_PROCESS_EVENT__

#include "bpf_helpers.h"

#include "bpf_cgroup.h"

#define ENAMETOOLONG 36 /* File name too long */

struct buffer_heap_map_value {
	unsigned char buf[PATH_MAP_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct buffer_heap_map_value);
} buffer_heap_map SEC(".maps");

static inline __attribute__((always_inline)) __u64
__get_auid(struct task_struct *task)
{
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

static inline __attribute__((always_inline)) __u32 get_auid(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __get_auid(task);
}

static inline __attribute__((always_inline)) __u64
get_parent_auid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);

	return __get_auid(task);
}

#define offsetof_btf(s, memb) ((size_t)((char *)_(&((s *)0)->memb) - (char *)0))

#define container_of_btf(ptr, type, member)                      \
	({                                                       \
		void *__mptr = (void *)(ptr);                    \
		((type *)(__mptr - offsetof_btf(type, member))); \
	})

static inline __attribute__((always_inline)) struct mount *
real_mount(struct vfsmount *mnt)
{
	return container_of_btf(mnt, struct mount, mnt);
}

static inline __attribute__((always_inline)) bool IS_ROOT(struct dentry *dentry)
{
	struct dentry *d_parent;

	probe_read(&d_parent, sizeof(d_parent), _(&dentry->d_parent));
	return (dentry == d_parent);
}

static inline __attribute__((always_inline)) bool
hlist_bl_unhashed(const struct hlist_bl_node *h)
{
	struct hlist_bl_node **pprev;

	probe_read(&pprev, sizeof(pprev), _(&h->pprev));
	return !pprev;
}

static inline __attribute__((always_inline)) int
d_unhashed(struct dentry *dentry)
{
	return hlist_bl_unhashed(_(&dentry->d_hash));
}

static inline __attribute__((always_inline)) int
d_unlinked(struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

static inline __attribute__((always_inline)) int
prepend_name(char *bf, char **buffer, int *buflen, const char *name, u32 dlen)
{
	char slash = '/';
	u64 buffer_offset = (u64)(*buffer) - (u64)bf;

	// Change dlen (the dentry name length) to fit in the buffer.
	// We prefer to store the part of it that fits rather that discard it.
	if (dlen + 1 /* for the slash */ >= *buflen)
		dlen = *buflen - 1 /* for the slash */ -
		       1 /* in order to avoid the case to do *buflen == 0 */;

	*buflen -= (dlen + 1);
	// This will not happen as in the previous if-clause ensures that *buflen will be > 0
	// Needed to make the verifier happy in older kernels.
	if (*buflen <= 0)
		return -ENAMETOOLONG;

	buffer_offset -= (dlen + 1);

	// This will never happen. buffer_offset is the diff of the initial buffer pointer
	// with the current buffer pointer. This will be at max 256 bytes (similar to the initial
	// size).
	// Needed to bound that for probe_read call.
	if (buffer_offset > PATH_MAP_SIZE - 256)
		return -ENAMETOOLONG;

	probe_read(bf + buffer_offset, sizeof(char), &slash);
	// This ensures that dlen is < 256, which is aligned with kernel's max dentry name length
	// that is 255 (https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/limits.h#L12).
	// Needed to bound that for probe_read call.
	asm volatile("%[dlen] &= 0xff;\n" ::[dlen] "+r"(dlen)
		     :);
	probe_read(bf + buffer_offset + 1, dlen * sizeof(char), name);

	*buffer = bf + buffer_offset;
	return 0;
}

/*
 * Only called from path_with_deleted function before any path traversals.
 * In the current scenarios, always buflen will be 256 and namelen 10.
 * For this reason I will never return -ENAMETOOLONG.
 */
static inline __attribute__((always_inline)) int
prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0) // will never happen - check function comment
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

struct cwd_read_data {
	struct dentry *root_dentry;
	struct vfsmount *root_mnt;
	char *bf;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	char *bptr;
	int blen;
	bool resolved;
};

static inline __attribute__((always_inline)) long
cwd_read(struct cwd_read_data *data)
{
	struct qstr d_name;
	struct dentry *parent;
	struct dentry *vfsmnt_mnt_root;
	struct dentry *dentry = data->dentry;
	struct vfsmount *vfsmnt = data->vfsmnt;
	struct mount *mnt = data->mnt;
	int error;

	if (!(dentry != data->root_dentry || vfsmnt != data->root_mnt)) {
		data->resolved =
			true; // resolved all path components successfully
		return 1;
	}

	probe_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root),
		   _(&vfsmnt->mnt_root));
	if (dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
		struct mount *parent;

		probe_read(&parent, sizeof(parent), _(&mnt->mnt_parent));

		/* Global root? */
		if (data->mnt != parent) {
			probe_read(&data->dentry, sizeof(data->dentry),
				   _(&mnt->mnt_mountpoint));
			data->mnt = parent;
			probe_read(&data->vfsmnt, sizeof(data->vfsmnt),
				   _(&mnt->mnt));
			return 0;
		}
		// resolved all path components successfully
		data->resolved = true;
		return 1;
	}
	probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	error = prepend_name(data->bf, &data->bptr, &data->blen,
			     (const char *)d_name.name, d_name.len);
	// This will happen where the dentry name does not fit in the buffer.
	// We will stop the loop with resolved == false and later we will
	// set the proper value in error before function return.
	if (error)
		return 1;

	data->dentry = parent;
	return 0;
}

#ifdef __V60_BPF_PROG
static long cwd_read_v60(__u32 index, void *data)
{
	return cwd_read(data);
}
#endif

static inline __attribute__((always_inline)) int
prepend_path(const struct path *path, const struct path *root, char *bf,
	     char **buffer, int *buflen)
{
	struct cwd_read_data data = {
		.bf = bf,
		.bptr = *buffer,
		.blen = *buflen,
	};
	int error = 0;

	probe_read(&data.root_dentry, sizeof(data.root_dentry),
		   _(&root->dentry));
	probe_read(&data.root_mnt, sizeof(data.root_mnt), _(&root->mnt));
	probe_read(&data.dentry, sizeof(data.dentry), _(&path->dentry));
	probe_read(&data.vfsmnt, sizeof(data.vfsmnt), _(&path->mnt));
	data.mnt = real_mount(data.vfsmnt);

#ifndef __V60_BPF_PROG
#pragma unroll
	for (int i = 0; i < PROBE_CWD_READ_ITERATIONS; ++i) {
		if (cwd_read(&data))
			break;
	}
#else
	loop(PROBE_CWD_READ_ITERATIONS, cwd_read_v60, (void *)&data, 0);
#endif /* __V60_BPF_PROG */

	if (data.bptr == *buffer) {
		*buflen = 0;
		return 0;
	}
	if (!data.resolved)
		error = UNRESOLVED_PATH_COMPONENTS;
	*buffer = data.bptr;
	*buflen = data.blen;
	return error;
}

static inline __attribute__((always_inline)) int
path_with_deleted(const struct path *path, const struct path *root, char *bf,
		  char **buf, int *buflen)
{
	struct dentry *dentry;

	probe_read(&dentry, sizeof(dentry), _(&path->dentry));
	if (d_unlinked(dentry)) {
		int error = prepend(buf, buflen, " (deleted)", 10);
		if (error) // will never happen as prepend will never return a value != 0
			return error;
	}
	return prepend_path(path, root, bf, buf, buflen);
}

/*
 * This function returns the path of a dentry and works in a similar
 * way to Linux d_path function (https://elixir.bootlin.com/linux/v5.10/source/fs/d_path.c#L262).
 *
 * Input variables:
 * - 'path' is a pointer to a dentry path that we want to resolve
 * - 'buf' is the buffer where the path will be stored (this should be always the value of 'buffer_heap_map' map)
 * - 'buflen' is the available buffer size to store the path (now 256 in all cases, maybe we can increase that further)
 *
 * Input buffer layout:
 * <--        buflen         -->
 * -----------------------------
 * |                           |
 * -----------------------------
 * ^
 * |
 * buf
 *
 *
 * Output variables:
 * - 'buf' is where the path is stored (>= compared to the input argument)
 * - 'buflen' the size of the resolved path (0 < buflen <= 256). Will not be negative. If buflen == 0 nothing is written to the buffer.
 * - 'error' 0 in case of success or UNRESOLVED_PATH_COMPONENTS in the case where the path is larger than the provided buffer.
 *
 * Output buffer layout:
 * <--   buflen  -->
 * -----------------------------
 * |                /etc/passwd|
 * -----------------------------
 *                 ^
 *                 |
 *                buf
 *
 * ps. The size of the path will be (initial value of buflen) - (return value of buflen) if (buflen != 0)
 */
static inline __attribute__((always_inline)) char *
__d_path_local(const struct path *path, char *buf, int *buflen, int *error)
{
	char *res = buf + *buflen;
	struct task_struct *task;
	struct fs_struct *fs;

	task = (struct task_struct *)get_current_task();
	probe_read(&fs, sizeof(fs), _(&task->fs));
	*error = path_with_deleted(path, _(&fs->root), buf, &res, buflen);
	return res;
}

/*
 * Entry point to the codepath used for path resolution.
 *
 * This function allocates a buffer from 'buffer_heap_map' map and calls
 * __d_path_local. After __d_path_local returns, it also does the appropriate
 * calculations on the buffer size (check __d_path_local comment).
 *
 * Returns the buffer where the path is stored. 'buflen' is the size of the
 * resolved path (0 < buflen <= 256) and will not be negative. If buflen == 0
 * nothing is written to the buffer (still the value to the buffer is valid).
 * 'error' is 0 in case of success or UNRESOLVED_PATH_COMPONENTS in the case
 * where the path is larger than the provided buffer.
 */
static inline __attribute__((always_inline)) char *
d_path_local(const struct path *path, int *buflen, int *error)
{
	int zero = 0;
	char *buffer = 0;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	*buflen = 256;
	buffer = __d_path_local(path, buffer, buflen, error);
	if (*buflen > 0)
		*buflen = 256 - *buflen;

	return buffer;
}

static inline __attribute__((always_inline)) int64_t
getcwd(struct msg_process *curr, __u32 offset, __u32 proc_pid, bool prealloc)
{
	struct task_struct *task = get_task_from_pid(proc_pid);
	__u32 orig_size = curr->size, orig_offset = offset;
	struct fs_struct *fs;
	int flags = 0, size = 0;
	char *buffer;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		curr->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	buffer = d_path_local(_(&fs->pwd), &size, &flags);
	if (!buffer)
		return 0;

	asm volatile("%[offset] &= 0x3ff;\n" ::[offset] "+r"(offset)
		     :);
	asm volatile("%[size] &= 0xff;\n" ::[size] "+r"(size)
		     :);
	probe_read((char *)curr + offset, size, buffer);

	offset += size;
	curr->size = offset;
	// Unfortunate special case for '/' where nothing was added we need
	// to truncate with '\n' for parser.
	if (curr->size == orig_offset)
		curr->flags |= EVENT_ROOT_CWD;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		curr->flags |= EVENT_ERROR_PATH_COMPONENTS;

	/* If the size was preallocated from user space side (ProcFS entry)
	 * then we need to keep the same size so we can find parent/child
	 * entries.
	 */
	if (prealloc)
		curr->size = orig_size;
	return 0;
}

static inline __attribute__((always_inline)) void
event_set_clone(struct msg_process *pid)
{
	pid->flags |= EVENT_CLONE;
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
	probe_read(&msg->effective, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&msg->inheritable, sizeof(__u64), _(&cred->cap_inheritable));
	probe_read(&msg->permitted, sizeof(__u64), _(&cred->cap_permitted));
}

static inline __attribute__((always_inline)) void
get_namespaces(struct msg_ns *msg, struct task_struct *task)
{
	struct nsproxy *nsproxy;
	struct nsproxy nsp;

	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	probe_read(&nsp, sizeof(nsp), _(nsproxy));

	probe_read(&msg->uts_inum, sizeof(msg->uts_inum),
		   _(&nsp.uts_ns->ns.inum));
	probe_read(&msg->ipc_inum, sizeof(msg->ipc_inum),
		   _(&nsp.ipc_ns->ns.inum));
	probe_read(&msg->mnt_inum, sizeof(msg->mnt_inum),
		   _(&nsp.mnt_ns->ns.inum));
	{
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
	probe_read(&msg->pid_for_children_inum,
		   sizeof(msg->pid_for_children_inum),
		   _(&nsp.pid_ns_for_children->ns.inum));
	probe_read(&msg->net_inum, sizeof(msg->net_inum),
		   _(&nsp.net_ns->ns.inum));

	// this also includes time_ns_for_children
	if (bpf_core_field_exists(nsproxy->time_ns)) {
		probe_read(&msg->time_inum, sizeof(msg->time_inum),
			   _(&nsp.time_ns->ns.inum));
		probe_read(&msg->time_for_children_inum,
			   sizeof(msg->time_for_children_inum),
			   _(&nsp.time_ns_for_children->ns.inum));
	}

	probe_read(&msg->cgroup_inum, sizeof(msg->cgroup_inum),
		   _(&nsp.cgroup_ns->ns.inum));
	{
		struct mm_struct *mm;
		struct user_namespace *user_ns;

		probe_read(&mm, sizeof(mm), _(&task->mm));
		probe_read(&user_ns, sizeof(user_ns), _(&mm->user_ns));
		probe_read(&msg->user_inum, sizeof(msg->user_inum),
			   _(&user_ns->ns.inum));
	}
}

/* Gather current task cgroup id */
static inline __attribute__((always_inline)) void
__event_get_current_cgroup_id(struct tetragon_conf *conf, struct cgroup *cgrp,
			      struct execve_map_value *execve_val,
			      struct msg_execve_event *msg)
{
	__u64 cgrpfs_magic = 0;
	struct msg_process *process;

	process = &msg->process;
	msg->kube.cgrpid = 0;

	/* If tracking Cgroup ID is set use it, otherwise use current
	 * context one. This way we guarantee to always have a cgrpid
	 * and return cgroup information even if we miss the tracking
	 * Cgroup ID.
	 *
	 * Ensure that execve_val is not null.
	 */
	if (execve_val && execve_val->cgrpid_tracker) {
		/* Set the k8s cgrpid with the tracking ID. */
		msg->kube.cgrpid = execve_val->cgrpid_tracker;
		return;
	}

	/* Gather Cgroup information using current context */
	if (conf) {
		/* Select which cgroup version */
		cgrpfs_magic = conf->cgrp_fs_magic;
	}

	/* Collect event cgroup ID */
	msg->kube.cgrpid = tg_get_current_cgroup_id(cgrp, cgrpfs_magic);
	if (execve_val)
		execve_val->cgrpid_tracker = msg->kube.cgrpid;
	if (!msg->kube.cgrpid)
		process->flags |= EVENT_ERROR_CGROUP_ID;
}

/* Gather current task cgroup name */
static inline __attribute__((always_inline)) void
__event_get_current_cgroup_name(struct cgroup *cgrp,
				struct msg_execve_event *msg)
{
	const char *name;
	struct msg_process *process;

	process = &msg->process;

	/* TODO: check if we have Tetragon cgroup configuration and that the
	 *     tracking cgroup ID is set. If so then query the bpf map for
	 *     the corresponding tracking cgroup name.
	 */

	/* TODO: we gather current cgroup context, switch to tracker see above,
	 *    and if that fails for any reason or if we don't have the cgroup name
	 *    of tracker, then we can continue with current context.
	 */

	name = get_cgroup_name(cgrp);
	if (name)
		probe_read_str(msg->kube.docker_id, KN_NAME_LENGTH, name);
	else
		process->flags |= EVENT_ERROR_CGROUP_NAME;
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
static inline __attribute__((always_inline)) void
__event_get_cgroup_info(struct task_struct *task,
			struct msg_execve_event *msg)
{
	__u32 pid;
	int zero = 0, subsys_idx = 0;
	struct cgroup *cgrp;
	struct msg_process *process;
	struct tetragon_conf *conf;
	struct execve_map_value *execve_val;

	process = &msg->process;

	/* Clear cgroup info at the beginning, so if we return early we do not pass previous data */
	memset(&msg->kube, 0, sizeof(struct msg_k8s));

	pid = (get_current_pid_tgid() >> 32);
	execve_val = execve_map_get(pid);
	/* Even if execve_val is null we must continue collect information */

	/* Check if cgroup configuration is set */
	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf) {
		/* Select the right css to use */
		if (conf->tg_cgrp_subsys_idx != 0)
			subsys_idx = conf->tg_cgrp_subsys_idx;

		/* Set the tracking cgroup ID of the task if it was not
		 * already set, this could be the case due to race conditions.
		 * Do not remove this as following cgroup logic depend on it.
		 */
		__set_task_cgrpid_tracker(conf, task, execve_val, &process->flags);
	}

	cgrp = get_task_cgroup(task, subsys_idx, &process->flags);
	if (!cgrp)
		return;

	/* Collect event cgroup ID */
	__event_get_current_cgroup_id(conf, cgrp, execve_val, msg);

	/* Get the cgroup name of this event. TODO: pass the tracking cgroup ID. */
	__event_get_current_cgroup_name(cgrp, msg);
}

/* Pahole bug does not convert to btf correctly with arbitrary byte holes not
 * near a cacheline. To work-around this we can specify a define with the
 * CGROUPS_OFFSET we read directly out of debug_info section. Note other
 * reads, subsys[], cgroup are the first element of the structure so we can
 * "just" read those. Then cid, kn, and name all appear to be before byte
 * holes on kernels I checked so leave them alone for now.
 *
 * Todo, fix pahole to avoid doing extra steps to lookup offsets.
 * Edit: pahole has been fixed need to update toolchain.
 */
static inline __attribute__((always_inline)) void
__event_get_task_info(struct msg_execve_event *msg, __u8 op, bool walker,
		      bool cwd_always)
{
	struct msg_process *process;
	struct task_struct *task;

	msg->common.op = op;
	msg->common.ktime = ktime_get_ns();
	process = &msg->process;

	if (cwd_always || process->flags & EVENT_NEEDS_CWD) {
		__u32 offset;
		int err;
		bool prealloc = false;

		/* In the cwd always case we have no reserved memory for
		 * CWD so insert CWD directly after the curr->size. In
		 * EVENT_NEEDS_CWD case this is a procFS entry that we
		 * need to insert CWD for and memory has been reserved
		 * already. Finally if ERROR_CWD flag is set skip there
		 * is no point in continuing to bang on it if its not
		 * working.
		 */
		offset = process->size;
		if (!cwd_always) {
			offset -= CWD_MAX + 1;
			prealloc = true;
		}
		if (!(process->flags & EVENT_ERROR_CWD)) {
			err = getcwd(process, offset, process->pid, prealloc);
			if (!err)
				process->flags = process->flags & ~(EVENT_NEEDS_CWD |
								    EVENT_ERROR_CWD);
		}
	}
	if (process->flags & EVENT_NEEDS_AUID) {
		__u32 flags = process->flags & ~EVENT_NEEDS_AUID;

		process->auid = get_auid();
		process->flags = flags;
	}
	msg->common.size =
		offsetof(struct msg_execve_event, process) + process->size;
	process->uid = get_current_uid_gid();
	if (walker)
		process->flags |= EVENT_TASK_WALK;

	task = (struct task_struct *)get_current_task();
	BPF_CORE_READ_INTO(&msg->kube.net_ns, task, nsproxy, net_ns, ns.inum);

	get_current_subj_caps(&msg->caps, task);
	get_namespaces(&(msg->ns), task);

	/* Last operation: gather current task cgroup information */
	__event_get_cgroup_info(task, msg);
}
#endif
