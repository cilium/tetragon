// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __PROCESS_STORAGE_HASH_H__
#define __PROCESS_STORAGE_HASH_H__

/* Hash map backed process maps and helpers. Only to be included by process.h. */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct binary);
} tg_parents_bin SEC(".maps");

/* tgid+tid is key as execve is a complex syscall where failures
 * may happen at different levels and hooks, also the thread
 * that triggered and succeeded at execve will be the only new
 * and main thread.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct execve_info);
} tg_execve_joined_info_map SEC(".maps");

FUNC_INLINE void execve_joined_info_map_set(__u64 tid, struct execve_info *info)
{
	int err;

	err = map_update_elem(&tg_execve_joined_info_map, &tid, info, BPF_ANY);
	if (!err) {
		STATS_INC(tg_execve_joined_info_map_stats, COUNT);
	} else {
		/* -EBUSY or -ENOMEM with the help of the cntr error
		 * on the stats map this can be a good indication of
		 * long running workloads and if we have to make the
		 * map size bigger for such cases.
		 */
		STATS_INC(tg_execve_joined_info_map_stats, EUPDATE);
	}
}

/* Clear up some space for next threads */
FUNC_INLINE void execve_joined_info_map_clear(__u64 tid)
{
	long err;

	err = map_delete_elem(&tg_execve_joined_info_map, &tid);
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
	return map_lookup_elem(&tg_execve_joined_info_map, &tid);
}

#endif // __PROCESS_STORAGE_HASH_H__
