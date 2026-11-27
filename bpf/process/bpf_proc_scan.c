// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "compiler.h"
#include "bpf_helpers.h"
#include "bpf_task.h"
#include "process.h"
#include "bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/*
 * Startup scan of the running processes, an in-kernel replacement of the
 * procfs scan done by userspace (see pkg/sensors/exec/procevents).
 *
 * The program is run once from userspace via BPF_PROG_TEST_RUN. It walks all
 * the processes in the system with the open-coded task iterator, which starts
 * from init_task and is not bound to the pid namespace of the caller, so the
 * scan sees all the host processes even when tetragon runs in a pod without
 * hostPID.
 *
 * The scan is done in two passes:
 *  - the first pass walks the processes with the task iterator, which needs
 *    to run under an RCU read lock, and only records the pid and the start
 *    time of each of them in tg_proc_scan_map.
 *  - the second pass handles the recorded processes one by one. It first
 *    reads the process arguments with copy_from_user_task(), which can sleep
 *    and so is not allowed under RCU. Then, under an RCU read lock, it builds
 *    the execve_map entry, arguments included, and adds it unless the entry
 *    already exists (i.e. it was created by the exec/fork hooks in the
 *    meantime). Finally, it records the process in tg_proc_scan_map,
 *    together with the details userspace needs to build the startup execve
 *    events (credentials, cwd and cgroup), overwriting the first pass entries.
 *    Processes that could not be added to execve_map (i.e. the map is full)
 *    are recorded too, flagged with PROC_SCAN_NOT_IN_MAP, so that userspace
 *    still reports them as the procfs scan does.
 *
 * The execve_map entries are only added once complete, so that until then
 * the processes are handled as with the procfs scan: they have no entry, the
 * generic hooks fall back to the parent entry or to the current task and the
 * fork hook does not create entries for their children. An entry with no
 * arguments instead would make matchCmdArgs selectors fail, and would be
 * inherited by the children forked meanwhile.
 *
 * The program returns the number of processes recorded in tg_proc_scan_map,
 * or a negative error if a process could not be recorded (i.e. the map is
 * full), in which case the scan is incomplete and userspace falls back to the
 * procfs scan.
 */

#define PF_KTHREAD 0x00200000

/* Process ktime is the start time of the process in clock ticks (USER_HZ)
 * converted to ns, to match what the procfs scan reads from /proc/<pid>/stat
 * (see clktck in pkg/reader/proc). Exec IDs are built from the ktime, so this
 * keeps them stable across tetragon restarts and between the two scans.
 */
#define PROC_SCAN_TICK_NS (1000000000ULL / 100)

#define PROC_SCAN_ARGV0_MAX 4096
#define PROC_SCAN_CWD_MAX   4096

#define PROC_SCAN_KTHREAD   0x1
#define PROC_SCAN_CWD_ERROR 0x2
/* the process could not be added to execve_map, i.e. the map is full */
#define PROC_SCAN_NOT_IN_MAP 0x4
/* the cwd is truncated, it has more components than d_path_local() resolves */
#define PROC_SCAN_CWD_PATH_COMPONENTS 0x8

struct proc_scan_entry {
	__u32 pid;
	__u32 flags;
	__u64 ktime;
	/* uid, euid, suid, fsuid as in /proc/<pid>/status */
	__u32 uids[4];
	/* gid, egid, sgid, fsgid as in /proc/<pid>/status */
	__u32 gids[4];
	__u32 auid;
	/* cwd length, zero for the root directory */
	__u32 cwd_len;
	/* cgroup id and name, used to find the container id */
	struct msg_k8s kube;
	char cwd[PROC_SCAN_CWD_MAX];
}; // All fields aligned so no 'packed' attribute.

/* Entries are keyed by their index, from zero to the value returned by the
 * program. Without preallocation, the map only uses memory for the processes
 * actually running. Max entries are set by userspace.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_scan_entry);
} tg_proc_scan_map SEC(".maps");

struct proc_scan_heap {
	/* Number of processes recorded in tg_proc_scan_map, reused by both
	 * passes. It's kept in the map value rather than on the stack, so the
	 * verifier does not track it as a known value and the loop states can
	 * converge.
	 */
	__u32 cnt;
	__u32 pad;
	struct execve_map_value value;
	struct proc_scan_entry entry;
	struct heap_exe exe;
	struct args args;
	char argv0[PROC_SCAN_ARGV0_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_scan_heap);
} tg_proc_scan_heap SEC(".maps");

FUNC_INLINE __u64 proc_scan_ktime(struct task_struct *task)
{
	__u64 start = BPF_CORE_READ(task, group_leader, start_boottime);

	return start / PROC_SCAN_TICK_NS * PROC_SCAN_TICK_NS;
}

/* Kernel threads have no executable, use comm as the procfs scan does. */
FUNC_INLINE void proc_scan_read_comm(struct task_struct *task, struct heap_exe *exe)
{
	long len;

	len = probe_read_str(exe->buf, sizeof(task->comm), _(&task->comm));
	if (len <= 1) {
		exe->len = 0;
		return;
	}
	/* don't include the NULL byte in the length */
	exe->len = len - 1;
	/* comm fits in the postfix buffer, so the postfix is the whole comm */
	__bpf_memcpy_builtin(exe->end, exe->buf, sizeof(task->comm));
}

/* Same as getcwd(). The path is resolved against the root of the current
 * task, like the procfs scan does when reading /proc/<pid>/cwd.
 */
FUNC_INLINE void proc_scan_read_cwd(struct task_struct *task, struct proc_scan_entry *entry)
{
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	int size = 0, flags = 0;
	char *buffer;

	entry->cwd_len = 0;
	if (!fs) {
		entry->flags |= PROC_SCAN_CWD_ERROR;
		return;
	}

	buffer = d_path_local(_(&fs->pwd), &size, &flags);
	if (!buffer) {
		entry->flags |= PROC_SCAN_CWD_ERROR;
		return;
	}

	asm volatile("%[size] &= 0xfff;\n"
		     : [size] "+r"(size));
	if (probe_read(entry->cwd, size, buffer)) {
		entry->flags |= PROC_SCAN_CWD_ERROR;
		return;
	}
	entry->cwd_len = size;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		entry->flags |= PROC_SCAN_CWD_PATH_COMPONENTS;
}

FUNC_INLINE long
proc_scan_record(struct task_struct *task, const struct cred *cred,
		 struct proc_scan_heap *heap, __u32 flags)
{
	struct execve_map_value *value = &heap->value;
	struct proc_scan_entry *entry = &heap->entry;
	__u32 idx = heap->cnt;
	long err;

	entry->pid = value->key.pid;
	entry->flags = flags;
	entry->ktime = value->key.ktime;
	entry->uids[0] = BPF_CORE_READ(cred, uid.val);
	entry->uids[1] = BPF_CORE_READ(cred, euid.val);
	entry->uids[2] = BPF_CORE_READ(cred, suid.val);
	entry->uids[3] = BPF_CORE_READ(cred, fsuid.val);
	entry->gids[0] = BPF_CORE_READ(cred, gid.val);
	entry->gids[1] = BPF_CORE_READ(cred, egid.val);
	entry->gids[2] = BPF_CORE_READ(cred, sgid.val);
	entry->gids[3] = BPF_CORE_READ(cred, fsgid.val);
	entry->auid = __get_auid(task);
	proc_scan_read_cwd(task, entry);
	/* task is not current: we run from the second pass of the scan */
	__event_get_task_cgroup_info(task, &entry->kube, false);

	err = map_update_elem(&tg_proc_scan_map, &idx, entry, BPF_ANY);
	if (!err)
		heap->cnt = idx + 1;
	return err;
}

/* Read the process arguments, excluding argv[0], same as read_task_args_source()
 * and copy_args() do for the current task. It can sleep, so it must not be
 * called under RCU.
 */
FUNC_INLINE void
proc_scan_args(struct task_struct *task, struct proc_scan_heap *heap)
{
	unsigned long start, end;
	struct mm_struct *mm;
	__u64 len;
	__u32 off = 0;
	int i;

	heap->args.len = 0;

	/* kernel threads have no arguments */
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return;
	start = BPF_CORE_READ(mm, arg_start);
	end = BPF_CORE_READ(mm, arg_end);
	if (!start || end <= start)
		return;

	len = end - start;
	if (len > PROC_SCAN_ARGV0_MAX)
		len = PROC_SCAN_ARGV0_MAX;
	if (copy_from_user_task(heap->argv0, len, (void *)start, task, 0))
		return;

	bpf_for(i, 0, len)
	{
		if (!heap->argv0[i]) {
			off = i + 1;
			break;
		}
	}
	if (!off)
		return;

	len = end - start - off;
	if (len > sizeof(heap->args.buf))
		len = sizeof(heap->args.buf);
	if (len && !copy_from_user_task(heap->args.buf, len, (void *)start + off, task, 0))
		heap->args.len = len;
}

/* Global function, so the verifier checks it once rather than on every
 * iteration of the second pass loop, where the states of this (large) body
 * would not converge and the program would hit the complexity limit.
 * The arguments must have been read in heap->args already.
 */
__attribute__((noinline)) int
proc_scan_task(struct task_struct *task __arg_trusted, struct proc_scan_heap *heap __arg_nonnull)
{
	struct execve_map_value *value = &heap->value;
	struct execve_map_value *parent;
	struct task_struct *ptask;
	const struct cred *cred;
	__u32 pid, flags = 0;
	long err;

	pid = BPF_CORE_READ(task, tgid);

	__bpf_memset_builtin(value, 0, sizeof(*value));
	value->key.pid = pid;
	value->key.ktime = proc_scan_ktime(task);

	ptask = BPF_CORE_READ(task, real_parent);
	value->pkey.pid = BPF_CORE_READ(ptask, tgid);
	if (value->pkey.pid)
		value->pkey.ktime = proc_scan_ktime(ptask);

	/* zero for processes in the initial pid namespace */
	value->nspid = get_task_pid_vnr_by_task(task);
	get_namespaces(&value->ns, task);
	/* Objective credentials, as reported by /proc/<pid>/status. Read them
	 * once, so that the caps and the uids/gids come from the same cred.
	 */
	cred = BPF_CORE_READ(task, real_cred);
	__get_caps(&value->caps, cred);

	heap->exe.len = 0;
	heap->exe.error = 0;
	if (BPF_CORE_READ(task, flags) & PF_KTHREAD) {
		flags |= PROC_SCAN_KTHREAD;
		proc_scan_read_comm(task, &heap->exe);
	} else {
		read_exe(task, &heap->exe);
	}
	copy_exe_to_bin(&heap->exe, &value->bin);
	__bpf_memcpy_builtin(&value->args, &heap->args, sizeof(value->args));

	/* Processes are handled in fork order, so the parent was already added
	 * unless the process got reparented.
	 */
	parent = execve_map_get_noinit(value->pkey.pid);
	set_in_init_tree(value, parent);

	err = map_update_elem(&execve_map, &pid, value, BPF_NOEXIST);
	/* the exec/fork hooks already track this process */
	if (err == -EEXIST)
		return 0;
	if (err) {
		STATS_INC(execve_map_stats, EUPDATE);
		flags |= PROC_SCAN_NOT_IN_MAP;
	} else {
		STATS_INC(execve_map_stats, COUNT);
	}

	return proc_scan_record(task, cred, heap, flags);
}

SEC("syscall")
int proc_scan(void *ctx)
{
	struct proc_scan_entry *entry;
	struct proc_scan_heap *heap;
	struct task_struct *task;
	__u32 zero = 0, idx, cnt, pid;
	__u64 ktime;
	int i, err = 0;

	heap = map_lookup_elem(&tg_proc_scan_heap, &zero);
	if (!heap)
		return 0;

	/* First pass: record the pid and start time of every process. */
	heap->cnt = 0;
	bpf_rcu_read_lock();
	bpf_for_each(task, task, NULL, BPF_TASK_ITER_ALL_PROCS)
	{
		pid = BPF_CORE_READ(task, tgid);
		/* idle task, the kernel entry is added by userspace */
		if (!pid)
			continue;
		heap->entry.pid = pid;
		heap->entry.ktime = proc_scan_ktime(task);
		idx = heap->cnt;
		err = map_update_elem(&tg_proc_scan_map, &idx, &heap->entry, BPF_ANY);
		/* the process could not be recorded, the scan is incomplete */
		if (err)
			break;
		heap->cnt = idx + 1;
	}
	bpf_rcu_read_unlock();
	if (err)
		return err;

	/* Second pass: add the execve_map entries and record the processes
	 * still running, from the start of tg_proc_scan_map. The entry i is
	 * only overwritten once read, as the processes are recorded at an
	 * index lower than or equal to it.
	 */
	cnt = heap->cnt;
	heap->cnt = 0;
	bpf_for(i, 0, cnt)
	{
		entry = map_lookup_elem(&tg_proc_scan_map, &i);
		if (!entry)
			continue;
		pid = entry->pid;
		ktime = entry->ktime;

		task = bpf_task_from_pid(pid);
		/* the process exited */
		if (!task)
			continue;
		/* the process exited and the pid was reused, the new process
		 * is tracked by the exec/fork hooks
		 */
		if (proc_scan_ktime(task) != ktime) {
			bpf_task_release(task);
			continue;
		}

		proc_scan_args(task, heap);
		bpf_rcu_read_lock();
		err = proc_scan_task(task, heap);
		bpf_rcu_read_unlock();
		bpf_task_release(task);
		/* the process could not be recorded, the scan is incomplete */
		if (err)
			return err;
	}

	/* Drop the first pass entries left past the recorded processes. */
	bpf_for(i, heap->cnt, cnt)
	{
		idx = i;
		map_delete_elem(&tg_proc_scan_map, &idx);
	}
	return heap->cnt;
}
