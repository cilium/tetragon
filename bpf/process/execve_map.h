// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#include "lib/process.h"

typedef __u64 mbset_t;

// This structure stores the binary path that was recorded on execve.
// Technically PATH_MAX is 4096 but we limit the length we store since we have
// limits on the length of the string to compare:
// - Artificial limits for full string comparison.
// - Technical limits for prefix and postfix, using LPM_TRIE that have a 256
//   bytes size limit.
struct binary {
	// length of the path stored in path, this should be < BINARY_PATH_MAX_LEN
	// but can contain negative value in case of copy error.
	// While s16 would be sufficient, 32 bits are handy for alignment.
	__s32 path_length;
	// if end_r contains reversed path postfix
	__u32 reversed;
	// BINARY_PATH_MAX_LEN first bytes of the path
	char path[BINARY_PATH_MAX_LEN];
	// STRING_POSTFIX_MAX_LENGTH last bytes of the path
	char end[STRING_POSTFIX_MAX_LENGTH];
	// STRING_POSTFIX_MAX_LENGTH reversed last bytes of the path
	char end_r[STRING_POSTFIX_MAX_LENGTH];
	// args for the binary
	char args[MAXARGLENGTH];
	// matchBinary bitset for binary
	// NB: everything after and including ->mb_bitset will not be zeroed on a new exec. See
	// binary_reset().
	mbset_t mb_bitset;
	// mb generation value aka last mbset filter timestamp
	__u64 mb_gen;
}; // All fields aligned so no 'packed' attribute

FUNC_INLINE void
binary_reset(struct binary *b)
{
	// buffer can be written at clone stage with parent's info, if previous path is longer than
	// current, we can have leftovers at the end, so zero out bin structure.
	//
	// Do not zero the ->mb_bitset however, so that it can be inherited if exec() is called.
	// This depends on ->mb_bitset being the last part of the struct.
	memset(b, 0, offsetof(struct binary, mb_bitset));
}

// The execve_map_value is tracked by the TGID of the thread group
// the msg_execve_key.pid. The thread IDs are recorded on the
// fly and sent with every corresponding event.
struct execve_map_value {
	struct msg_execve_key key;
	struct msg_execve_key pkey;
	__u32 flags;
	__u32 nspid;
	struct msg_ns ns;
	struct msg_capabilities caps;
	struct binary bin;
} __attribute__((packed)) __attribute__((aligned(8)));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct execve_map_value);
} execve_map SEC(".maps");

enum {
	MAP_STATS_COUNT = 0,
	MAP_STATS_EUPDATE = 1,
	MAP_STATS_EDELETE = 2,
	MAP_STATS_MAX = 3,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAP_STATS_MAX);
	__type(key, __s32);
	__type(value, __s64);
} execve_map_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct execve_map_value);
} execve_val SEC(".maps");

struct execve_heap {
	union {
		char pathname[PATHNAME_SIZE];
		char maxpath[4096];
	};
	struct execve_info info;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct execve_heap);
} execve_heap SEC(".maps");

/* The tg_execve_joined_info_map allows to join and combine
 * exec info that is gathered during different hooks
 * through the execve call. The list of current hooks is:
 *   1. kprobe/security_bprm_committing_creds
 *      For details check tg_kp_bprm_committing_creds bpf program.
 *   2. tracepoint/sys_execve
 *      For details see event_execve bpf program.
 *
 * Important: the information stored here is complementary
 * information only, the core logic should not depend on entries
 * of this map to be present.
 *
 * tgid+tid is key as execve is a complex syscall where failures
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

/* The tg_execve_joined_info_map_stats will hold stats about
 * entries and map update errors.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAP_STATS_MAX);
	__type(key, __s32);
	__type(value, __s64);
} tg_execve_joined_info_map_stats SEC(".maps");

FUNC_INLINE void stats_update(struct bpf_map_def *map, __u32 key, int inc)
{
	__s64 *cntr;

	cntr = map_lookup_elem(map, &key);
	if (cntr)
		*cntr = *cntr + inc;
}

#define STATS_INC(map, key) stats_update((struct bpf_map_def *)&(map), MAP_STATS_##key, 1)
#define STATS_DEC(map, key) stats_update((struct bpf_map_def *)&(map), MAP_STATS_##key, -1)

// execve_map_get will look up if pid exists and return it if it does. If it
// does not, it will create a new one and return it.
FUNC_INLINE struct execve_map_value *execve_map_get(__u32 pid)
{
	struct execve_map_value *event;

	event = map_lookup_elem(&execve_map, &pid);
	if (!event) {
		struct execve_map_value *value;
		int err, zero = MAP_STATS_COUNT;

		value = map_lookup_elem(&execve_val, &zero);
		if (!value)
			return 0;

		memset(value, 0, sizeof(struct execve_map_value));
		err = map_update_elem(&execve_map, &pid, value, 0);
		if (!err) {
			STATS_INC(execve_map_stats, COUNT);
		} else {
			STATS_INC(execve_map_stats, EUPDATE);
		}
		event = map_lookup_elem(&execve_map, &pid);
	}
	return event;
}

FUNC_INLINE struct execve_map_value *execve_map_get_noinit(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}

FUNC_INLINE void execve_map_delete(__u32 pid)
{
	int err = map_delete_elem(&execve_map, &pid);

	if (!err) {
		STATS_DEC(execve_map_stats, COUNT);
	} else {
		STATS_INC(execve_map_stats, EDELETE);
	}
}

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
	int err;

	err = map_delete_elem(&tg_execve_joined_info_map, &tid);
	if (!err) {
		STATS_DEC(tg_execve_joined_info_map_stats, COUNT);
	} else {
		STATS_INC(tg_execve_joined_info_map_stats, EDELETE);
	}
	/* We don't care here about -ENOENT as there is no guarantee entries
	 * will be present anyway.
	 */
}

/* Returns an execve_info if found. A missing entry is perfectly fine as it
 * could mean we are not interested into storing more information about this task.
 */
FUNC_INLINE struct execve_info *execve_joined_info_map_get(__u64 tid)
{
	return map_lookup_elem(&tg_execve_joined_info_map, &tid);
}

_Static_assert(sizeof(struct execve_map_value) % 8 == 0,
	       "struct execve_map_value should have size multiple of 8 bytes");

FUNC_INLINE struct execve_map_value *
__event_find_parent(struct task_struct *task)
{
	__u32 pid;
	struct execve_map_value *value = 0;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read_kernel(&task, sizeof(task), _(&task->real_parent));
		if (!task)
			break;
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			return value;
	}
	return 0;
}

FUNC_INLINE struct execve_map_value *event_find_parent(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __event_find_parent(task);
}

FUNC_INLINE void event_minimal_curr(struct execve_map_value *event)
{
	event->key.pid = (get_current_pid_tgid() >> 32);
	event->key.ktime = 0; // should we insert a time?
	event->flags = EVENT_MISS;
}

FUNC_INLINE struct execve_map_value *event_find_curr(__u32 *ppid, bool *walked)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct execve_map_value *value = 0;
	int i;
	__u32 pid;

#pragma unroll
	for (i = 0; i < 4; i++) {
		probe_read_kernel(&pid, sizeof(pid), _(&task->tgid));
		value = execve_map_get_noinit(pid);
		if (value && value->key.ktime != 0)
			break;
		value = 0;
		*walked = 1;
		probe_read_kernel(&task, sizeof(task), _(&task->real_parent));
		if (!task)
			break;
	}
	*ppid = pid;
	return value;
}
