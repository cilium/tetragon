// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* tg_mbset_map holds a mapping from (binary) paths to a bitset of ids that it matches. The map is
 * written by user-space and read in the exec hook to determine the bitset of ids of a binary that
 * is executed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u8[MATCH_BINARIES_PATH_MAX_LENGTH]);
	__type(value, mbset_t);
} tg_mbset_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tg_mbset_gen SEC(".maps");

#ifdef __V511_BPF_PROG
FUNC_INLINE
void update_mb_task(struct execve_map_value *task)
{
	struct execve_map_value *last = NULL, *parent = task;
	__u64 *bitsetp, *gen;
	__u32 idx = 0;

	gen = map_lookup_elem(&tg_mbset_gen, &idx);
	if (!gen)
		return;
	if (*gen == task->bin.mb_gen)
		return;

	for (idx = 0; idx < 1024; idx++) {
		parent = execve_map_get_noinit(parent->pkey.pid);
		if (!parent || parent == last)
			break;
		bitsetp = map_lookup_elem(&tg_mbset_map, parent->bin.path);
		if (bitsetp && *bitsetp)
			__sync_fetch_and_or(&task->bin.mb_bitset, *bitsetp);
		last = parent;
	}

	task->bin.mb_gen = *gen;
}
#else
#define update_mb_task(task)
#endif /* __V511_BPF_PROG */
