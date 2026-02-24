// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATELIMIT_MAPS_H__
#define __RATELIMIT_MAPS_H__

/* Can't really include generic.h in here..
 */
#define MAX_POSSIBLE_ARGS 5

/* Rate limit scope. */
#define ACTION_RATE_LIMIT_SCOPE_THREAD	0
#define ACTION_RATE_LIMIT_SCOPE_PROCESS 1
#define ACTION_RATE_LIMIT_SCOPE_GLOBAL	2

/* FNV-1a hash constants for 64-bit. */
#define FNV1A_64_INIT  ((__u64)0xcbf29ce484222325ULL)
#define FNV1A_64_PRIME ((__u64)0x100000001b3ULL)

/*
 * Maximum bytes of each argument to hash for the rate-limit dedup key.
 *
 * We hash up to MAX_HASH_BYTES of each arg with FNV-1a, producing
 * one u64 per arg. copy_path() already caps paths at 255 bytes
 * (size &= 0xff), so 255 matches that cap exactly and fits within
 * the BPF verifier loop bound.
 */
#define MAX_HASH_BYTES 255

/*
 * FNV-1a hash of up to MAX_HASH_BYTES of src into a single u64.
 */
static inline __attribute__((always_inline)) __u64
fnv1a_hash_bytes(char *src, __u32 len)
{
	__u64 hash = FNV1A_64_INIT;
	__u32 i;

	if (len > MAX_HASH_BYTES)
		len = MAX_HASH_BYTES;
	/* Mask len so the verifier can prove the loop bound. */
	asm volatile("%[len] &= 0xff;\n"
		     : [len] "+r"(len)
		     :);

	for (i = 0; i < MAX_HASH_BYTES; i++) {
		if (i >= len)
			break;
		hash ^= (__u64)(__u8)src[i];
		hash *= FNV1A_64_PRIME;
	}
	return hash;
}

struct ratelimit_key {
	__u64 func_id;
	__u64 action;
	__u64 tid;
	__u64 arg_hash[MAX_POSSIBLE_ARGS];
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[sizeof(struct ratelimit_key) + MAX_HASH_BYTES]); // Extra headroom after the key for probe_read scratch space.
} ratelimit_heap SEC(".maps");

#endif /* __RATELIMIT_MAPS_H__ */
