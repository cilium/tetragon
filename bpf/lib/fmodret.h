// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __FMODRET_H__
#define __FMODRET_H__

#if (defined(SHARED_KPROBE) && defined(GENERIC_KPROBE)) || defined(GENERIC_FMODRET)
/* Only the handoff from a matching kprobe to its fmod_ret program is shared.
 * Selector evaluation and policy state remain in the policy's maps.
 */
struct fmodret_key {
	__u64 pid_tgid;
	__u64 target;
};

struct fmodret_action {
	__u32 scope;
	__s32 error;
	__u64 generation;
};

struct fmodret_binding {
	__u64 target;
	__u64 generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
	__type(key, struct fmodret_key);
	__type(value, struct fmodret_action);
} fmodret_tasks SEC(".maps");

/* A generation prevents a revoked action from using a recycled scope. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct fmodret_binding);
} fmodret_targets SEC(".maps");

#endif

#endif /* __FMODRET_H__ */
