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
 *  - the first pass runs under RCU and adds an execve_map entry for every
 *    process, unless the entry already exists (i.e. it was created by the
 *    exec/fork hooks in the meantime). It also records each process not
 *    already tracked in tg_proc_scan_map, together with the details userspace
 *    needs to build the startup execve events (credentials, cwd and cgroup).
 *    Processes that could not be added to execve_map (i.e. the map is full)
 *    are recorded too, flagged with PROC_SCAN_NOT_IN_MAP, so that userspace
 *    still reports them as the procfs scan does.
 *  - the second pass reads the arguments of the recorded processes. Reading
 *    another process memory with copy_from_user_task() can sleep, which is not
 *    allowed under RCU, hence the separate pass.
 *
 * The program returns the number of processes recorded in tg_proc_scan_map.
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
	/* Number of processes added to execve_map. It's kept in the map value
	 * rather than on the stack, so the verifier does not track it as a
	 * known value and the task iterator loop states can converge.
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
	probe_read_str(exe->end, sizeof(task->comm), _(&task->comm));
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
	if (probe_read(entry->cwd, size, buffer))
		entry->flags |= PROC_SCAN_CWD_ERROR;
	else
		entry->cwd_len = size;
}

FUNC_INLINE void
proc_scan_record(struct task_struct *task, struct proc_scan_heap *heap, __u32 flags)
{
	struct execve_map_value *value = &heap->value;
	struct proc_scan_entry *entry = &heap->entry;
	const struct cred *cred;
	__u32 idx = heap->cnt;

	cred = BPF_CORE_READ(task, real_cred);
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
	/* task is not current: we run from the iterator */
	__event_get_task_cgroup_info(task, &entry->kube, false);

	if (!map_update_elem(&tg_proc_scan_map, &idx, entry, BPF_ANY))
		heap->cnt = idx + 1;
}

/* Global function, so the verifier checks it once rather than on every
 * iteration of the task iterator loop, where the states of this (large) body
 * would not converge and the program would hit the complexity limit.
 */
__attribute__((noinline)) int
proc_scan_task(struct task_struct *task __arg_trusted, struct proc_scan_heap *heap __arg_nonnull)
{
	struct execve_map_value *value = &heap->value;
	struct execve_map_value *parent;
	struct task_struct *ptask;
	__u32 pid, flags = 0;
	long err;

	pid = BPF_CORE_READ(task, tgid);
	/* idle task, the kernel entry is added by userspace */
	if (!pid)
		return 0;

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
	/* objective credentials, as reported by /proc/<pid>/status */
	__get_caps(&value->caps, BPF_CORE_READ(task, real_cred));

	heap->exe.len = 0;
	heap->exe.error = 0;
	if (BPF_CORE_READ(task, flags) & PF_KTHREAD) {
		flags |= PROC_SCAN_KTHREAD;
		proc_scan_read_comm(task, &heap->exe);
	} else {
		read_exe(task, &heap->exe);
	}
	copy_exe_to_bin(&heap->exe, &value->bin);

	/* Processes are walked in fork order, so the parent was already added
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

	proc_scan_record(task, heap, flags);
	return 0;
}

/* Read the process arguments, excluding argv[0], same as read_task_args_source()
 * and copy_args() do for the current task.
 */
FUNC_INLINE void
proc_scan_args(struct proc_scan_entry *entry, struct proc_scan_heap *heap)
{
	struct execve_map_value *curr;
	struct task_struct *task;
	unsigned long start, end;
	struct mm_struct *mm;
	__u64 len;
	__u32 off = 0;
	int i;

	task = bpf_task_from_pid(entry->pid);
	if (!task)
		return;

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		goto out;
	start = BPF_CORE_READ(mm, arg_start);
	end = BPF_CORE_READ(mm, arg_end);
	if (!start || end <= start)
		goto out;

	len = end - start;
	if (len > PROC_SCAN_ARGV0_MAX)
		len = PROC_SCAN_ARGV0_MAX;
	if (copy_from_user_task(heap->argv0, len, (void *)start, task, 0))
		goto out;

	bpf_for(i, 0, len)
	{
		if (!heap->argv0[i]) {
			off = i + 1;
			break;
		}
	}
	if (!off)
		goto out;

	heap->args.len = 0;
	len = end - start - off;
	if (len > sizeof(heap->args.buf))
		len = sizeof(heap->args.buf);
	if (len && !copy_from_user_task(heap->args.buf, len, (void *)start + off, task, 0))
		heap->args.len = len;

	/* The copies above can sleep, look up the entry only now so that it's
	 * not freed and reused under us, and check it is still the process we
	 * scanned.
	 */
	curr = execve_map_get_noinit(entry->pid);
	if (curr && curr->key.ktime == entry->ktime)
		__bpf_memcpy_builtin(&curr->args, &heap->args, sizeof(curr->args));
out:
	bpf_task_release(task);
}

SEC("syscall")
int proc_scan(void *ctx)
{
	struct proc_scan_entry *entry;
	struct proc_scan_heap *heap;
	struct task_struct *task;
	__u32 zero = 0, cnt;
	int i;

	heap = map_lookup_elem(&tg_proc_scan_heap, &zero);
	if (!heap)
		return 0;

	heap->cnt = 0;
	bpf_rcu_read_lock();
	bpf_for_each(task, task, NULL, BPF_TASK_ITER_ALL_PROCS)
	{
		proc_scan_task(task, heap);
	}
	bpf_rcu_read_unlock();

	cnt = heap->cnt;
	bpf_for(i, 0, cnt)
	{
		entry = map_lookup_elem(&tg_proc_scan_map, &i);
		if (!entry)
			break;
		/* kernel threads have no arguments, and the processes not in
		 * execve_map have no entry to store them
		 */
		if (entry->flags & (PROC_SCAN_KTHREAD | PROC_SCAN_NOT_IN_MAP))
			continue;
		proc_scan_args(entry, heap);
	}
	return cnt;
}
