// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_MBSET_H__
#define __BPF_MBSET_H__

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

/* update bitset mark */
FUNC_INLINE
void update_mb_bitset(struct binary *bin)
{
	__u64 *bitsetp;
	struct execve_map_value *parent;

	parent = event_find_parent();
	if (parent) {
		/* ->mb_bitset is used to track matchBinary matches to children (followChildren), so
		 * here we propagate the parent value to the child.
		 */
		lock_or(&bin->mb_bitset, parent->bin.mb_bitset);
	}

	/* check the map and see if the binary path matches a binary */
	bitsetp = map_lookup_elem(&tg_mbset_map, bin->path);
	if (bitsetp)
		lock_or(&bin->mb_bitset, *bitsetp);
}

#endif /* __BPF_MBSET_H__ */
