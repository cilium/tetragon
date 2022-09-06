// SPDX-License-Identifier: GPL-2.0
// Copyright Authors of Tetragon

#include "vmlinux.h"
#include "api.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common.h"
#include "bpf_events.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

union cap_value {
	kernel_cap_t base;
	__u64 val;
};

struct task_iter_proc {
	__u32 pid;
	__u32 nspid;
	__u64 ktime;
	__u32 ppid;
	__u32 pnspid;
	__u64 pktime;
	__u64 effective;
	__u64 inheritable;
	__u64 permitted;
	__u32 uts_inum;
	__u32 ipc_inum;
	__u32 mnt_inum;
	__u32 pid_inum;
	__u32 pid_for_children_inum;
	__u32 net_inum;
	__u32 time_inum;
	__u32 time_for_children_inum;
	__u32 cgroup_inum;
	__u32 user_inum;
	__u32 uid;
	__u32 auid;
	__u32 size;
} __attribute__((packed));

#define ITER_ARGS_LAST	1
#define ITER_ARGS_ERROR 2
#define ITER_ARGS_FILE	4
#define ITER_ARGS_ARGS	8

struct task_iter_args {
	__u32 size;
	__u32 flags;
	__u8 data[16384]; // &= 0x3fff
} __attribute__((packed));

struct task_iter {
	union {
		struct task_iter_proc proc;
		struct task_iter_args args;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct task_iter);
} iter_heap SEC(".maps");

static inline __attribute__((always_inline)) __u64
task_ktime(struct task_struct *task)
{
	__u64 ktime = BPF_CORE_READ(task, start_time);

	return ktime;
}

__attribute__((section("iter.s/task"), used)) int
dump_task(struct bpf_iter__task *ctx)
{
	unsigned long arg_start, arg_end, total = 0, size = 0;
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	struct task_iter_proc *p;
	struct task_iter_args *a;
	struct task_iter *iter;
	union cap_value cap;
	__u32 zero = 0;
	int i;

	/* We send to user 2 types of events/messages:
	 *   1) struct task_iter_proc
	 *   2) struct task_iter_args
	 *
	 * Ad 1) is sent just once for task and contains all the details
	 * we need about task.
	 *
	 * Ad 2) contains program's arguments data and is sent multiple
	 * times to ensure all the arguments are sent to user space.
	 */
	if (task == (void *)0)
		return 0;

	iter = map_lookup_elem(&iter_heap, &zero);
	if (!iter)
		return 0;

	p = &iter->proc;

	/* pid/ktime/nspid */
	p->pid = BPF_CORE_READ(task, tgid);
	p->ktime = task_ktime(task);
	p->nspid = get_task_pid_vnr_task(task);

	/* effective/inheritable/permitted */
	cap.base = BPF_CORE_READ(task, cred, cap_effective);
	p->effective = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_inheritable);
	p->inheritable = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_permitted);
	p->permitted = cap.val;

	// uts_inum/ipc_inum/mnt_inum
	p->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
	p->ipc_inum = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
	p->mnt_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	// pid_inum
	struct upid *up = 0;
	unsigned int level;
	struct pid *pid;

	__builtin_preserve_access_index(({
		pid = task->thread_pid;
		if (pid) {
			level = pid->level & 0xf;
			up = &pid->numbers[level];
		}
	}));

	if (up)
		p->pid_inum = BPF_CORE_READ(up, ns, ns.inum);
	else
		p->pid_inum = 0;

	// pid_for_children_inum/net_inum/cgroup_inum/user_inum
	p->pid_for_children_inum =
		BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	p->net_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
	p->cgroup_inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	p->user_inum = BPF_CORE_READ(task, mm, user_ns, ns.inum);

	// time_for_children_inum
	if (bpf_core_field_exists(task->nsproxy->time_ns)) {
		p->time_inum = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
		p->time_for_children_inum = BPF_CORE_READ(
			task, nsproxy, time_ns_for_children, ns.inum);
	}

	// uid is not used at the moment
	p->uid = 0;

	// auid
	p->auid = 0;

	if (bpf_core_field_exists(task->loginuid)) {
		p->auid = BPF_CORE_READ(task, loginuid.val);
	} else if (bpf_core_field_exists(task->audit)) {
		if (BPF_CORE_READ(task, audit))
			p->auid = BPF_CORE_READ(task, audit, loginuid.val);
	}

	// ppid/pktime/pnspid
	parent = BPF_CORE_READ(task, parent);

	p->ppid = BPF_CORE_READ(parent, tgid);
	p->pktime = task_ktime(parent);
	p->pnspid = get_task_pid_vnr_task(parent);

	// args
	arg_start = BPF_CORE_READ(task, mm, arg_start);
	arg_end = BPF_CORE_READ(task, mm, arg_end);

	if (arg_end > arg_start)
		size = arg_end - arg_start;
	p->size = size;

	seq_write(seq, p, sizeof(*p));

	struct file *file = 0;
	struct path *path = 0;
	struct mm_struct *mm;
	long sz = 0;

	a = &iter->args;

	// program file path
	__builtin_preserve_access_index(({
		mm = task->mm;
		if (mm)
			file = mm->exe_file;
		if (file)
			path = &file->f_path;
	}));

	if (path)
		sz = d_path(path, (char *)&a->data[0], sizeof(a->data));

	// in case of failure, send down 'failed' string
	if (sz <= 0) {
		sz = 6;
		memcpy((char *)&a->data[0], "failed", sz);
		a->data[sz] = 0;
	}

	/* program file should fit in 4096 bytes, so we are good with
	 * single call to seq_write and 0x3fff buffer size
	 */
	a->flags = ITER_ARGS_FILE;
	a->size = (__u32)sz & 0x3fff;
	seq_write(seq, a, offsetof(struct task_iter_args, data) + a->size);

#define LOOP_CNT 200

	/* Program arguments size could be much bigger and it depends
	 * on local config, so let's try to send as much as possible:
	 * 200 * 16384 = 3276800 bytes
	 *
	 * We send arguments as one big data blob separated just by
	 * the size of the buffer, user space will do the parsing.
	 */
	for (i = 0; i < LOOP_CNT; i++) {
		unsigned long copy_size = sizeof(a->data);

		a->flags = 0;
		if (size < copy_size || i == (LOOP_CNT - 1)) {
			copy_size = size;
			a->flags = ITER_ARGS_LAST;
		}

		copy_size &= 0x3fff;
		if (copy_from_user_task(&a->data[0], copy_size,
					(const void *)arg_start + total, task,
					0)) {
			a->flags = ITER_ARGS_ERROR;
			a->size = 0;
		} else {
			a->size = copy_size;
			total += copy_size;
		}

		a->flags |= ITER_ARGS_ARGS;
		seq_write(seq, a,
			  offsetof(struct task_iter_args, data) + a->size);

		if (a->flags)
			break;
	}

#undef LOOP_CNT
	return 0;
}
