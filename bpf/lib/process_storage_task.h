// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __PROCESS_STORAGE_TASK_H__
#define __PROCESS_STORAGE_TASK_H__

/* Task storage backed process maps and helpers, used when __TASK_STORAGE is
 * defined. Only to be included by process.h, see process_storage_hash.h for
 * the hash map variant, which must expose the same API.
 */

/* With task storage the entry lives on the thread group leader task and it is
 * released by the kernel together with it, so no sizing or eviction is needed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct binary);
} tg_parents_bin SEC(".maps");

/* The entry is attached to the task running execve, which removes the need
 * for a key and lets the kernel release it when the task goes away.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct execve_info);
} tg_execve_joined_info_map SEC(".maps");

FUNC_INLINE void execve_joined_info_map_set(__u64 tid, struct execve_info *info)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	struct execve_info *value;

	value = task_storage_get(&tg_execve_joined_info_map, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (value) {
		__bpf_memcpy_builtin(value, info, sizeof(*value));
		STATS_INC(tg_execve_joined_info_map_stats, COUNT);
	} else {
		/* -ENOMEM or -EBUSY on recursion */
		STATS_INC(tg_execve_joined_info_map_stats, EUPDATE);
	}
}

/* Clear up some space for next threads */
FUNC_INLINE void execve_joined_info_map_clear(__u64 tid)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	long err;

	err = task_storage_delete(&tg_execve_joined_info_map, task);
	if (!err)
		STATS_DEC(tg_execve_joined_info_map_stats, COUNT);
	else
		STATS_INC(tg_execve_joined_info_map_stats, EDELETE);
	/* We don't care here about -ENOENT as there is no guarantee entries
	 * will be present anyway.
	 */
}

/* Returns the current task execve_info if found. A missing entry is perfectly
 * fine as it could mean we are not interested into storing more information
 * about this task.
 */
FUNC_INLINE struct execve_info *execve_joined_info_map_get(__u64 tid)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();

	return task_storage_get(&tg_execve_joined_info_map, task, 0, 0);
}

/* tg_parents_bin entries are per process, so they are stored on the thread
 * group leader. Task storage can only be reached through the task itself,
 * hence only the current process is supported, for any other pid there is
 * no entry.
 */
FUNC_INLINE struct task_struct *parents_bin_task(__u32 pid)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();

	/* Direct (CO-RE relocated) reads, the BTF pointer to the group leader
	 * is needed by the task storage helpers.
	 */
	if (*_(&task->tgid) != pid)
		return 0;
	return *_(&task->group_leader);
}

FUNC_INLINE struct binary *parents_bin_get(__u32 pid)
{
	struct task_struct *task = parents_bin_task(pid);

	if (!task)
		return 0;
	return task_storage_get(&tg_parents_bin, task, 0, 0);
}

FUNC_INLINE void parents_bin_update(__u32 pid, struct binary *bin)
{
	struct task_struct *task = parents_bin_task(pid);
	struct binary *value;

	if (!task)
		return;
	value = with_errmetrics_ptr(task_storage_get, &tg_parents_bin, task, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (value)
		__bpf_memcpy_builtin(value, bin, sizeof(*value));
}

FUNC_INLINE void parents_bin_delete(__u32 pid)
{
	struct task_struct *task = parents_bin_task(pid);

	if (task)
		task_storage_delete(&tg_parents_bin, task);
}

#endif // __PROCESS_STORAGE_TASK_H__
