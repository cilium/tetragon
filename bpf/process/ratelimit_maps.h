// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATELIMIT_MAPS_H__
#define __RATELIMIT_MAPS_H__

/* The number of bytes per argument to include in the key
 * that we use to check for repeating data.
 * 40 is good for IPv6 data.
 */
#define KEY_BYTES_PER_ARG 40

/* Can't really include generic.h in here..
 */
#define MAX_POSSIBLE_ARGS 5

/* Rate limit scope. */
#define ACTION_RATE_LIMIT_SCOPE_THREAD	0
#define ACTION_RATE_LIMIT_SCOPE_PROCESS 1
#define ACTION_RATE_LIMIT_SCOPE_GLOBAL	2

struct ratelimit_key {
	__u64 func_id;
	__u64 action;
	__u64 tid;
	__u8 data[MAX_POSSIBLE_ARGS * KEY_BYTES_PER_ARG];
};

struct ratelimit_value {
	__u64 ktime;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // Agent is resizing this if the feature is needed during kprobe load
	__type(key, struct ratelimit_key);
	__type(value, struct ratelimit_value);
} ratelimit_map SEC(".maps");

// The value has extra headroom to allow copying argument data without upsetting the verifier.
// This is not hashed when the key is used in the ratelimit_map.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[sizeof(struct ratelimit_key) + 128]);
} ratelimit_heap SEC(".maps");

// This is zeroed memory that we NEVER write to, and use to copy over reusable heap in order
// to zero it.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[sizeof(struct ratelimit_key) + 128]);
} ratelimit_ro_heap SEC(".maps");
#endif /* __RATELIMIT_MAPS_H__ */
