// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#ifndef __BPF_GLOB_H__
#define __BPF_GLOB_H__

#include "bpf_tracing.h"
#include "bpf_core_read.h"

#if !defined(MAX_GLOB_INPUT_SIZE)
#error "MAX_GLOB_INPUT_SIZE should be defined in order to use bpf_glob.h"
#endif

// the maximum number of possible values for each pattern (i.e. 0 to POSSIBLE_MAX_VALUES-1)
#define POSSIBLE_MAX_VALUES	 512 // this should match GlobPossibleMaxValues in pkg/glob/glob_multi_maps.go
#define POSSIBLE_MAX_VALUES_MASK (POSSIBLE_MAX_VALUES - 1)

#define BITMAP_SHIFT  6
#define BITMAP_MASK   63
#define BITS_PER_BYTE 8

struct __attribute__((aligned(8))) glob_bitmap {
	__u64 v[POSSIBLE_MAX_VALUES / BITS_PER_BYTE / sizeof(uint64_t) /* one bit per state */];
};

static inline __attribute__((always_inline)) int bitmap_read(struct glob_bitmap *b, int n)
{
	int word = n >> BITMAP_SHIFT;
	int position = n & BITMAP_MASK;

	return (b->v[word] >> position) & 1;
}

#define GLOB_TABLE_SIZE 256

struct glob_state_transitions {
	// Zero means that no transition exists. State IDs are stored as ID + 1.
	__s32 next[GLOB_TABLE_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1); // set this in userspace (number of states)
	__type(key, __s32); // state-id
	__type(value, struct glob_state_transitions);
} tg_glob_dfa SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // set this in user-space
	__type(key, __s32); // state-id
	__type(value, struct glob_bitmap); // bitmap with patterns that match
} tg_glob_final SEC(".maps");

// This function evaluates a 'path' with size 'len' size against the glob
// FSM stored in 'dfa'.
//
// Returns -1 if there is no match or the final state id otherwise.
// The final state id should be checked against tg_glob_final map to check
// if there is a match or not.
static inline __attribute__((always_inline)) __s32 check_pattern(void *dfa, char *path, __u32 len)
{
	__s32 state_id = 0;
	__u32 i;

	for (i = 0; i < MAX_GLOB_INPUT_SIZE; i++) {
		struct glob_state_transitions *transitions;
		__s32 next_state_id;
		__u8 cc;

		if (i >= len)
			return state_id;

		probe_read_kernel(&cc, sizeof(__u8), path + i);

		transitions = map_lookup_elem(dfa, &state_id);
		if (!transitions)
			return -1;

		next_state_id = transitions->next[cc];
		if (!next_state_id)
			return -1;

		state_id = next_state_id - 1;
	}

	return state_id;
}

// This checks 'state_id' against 'final' map to check if there is a match
// for *any* pattern. We don't really care about which pattern matches in
// this case.
//
// Returns 1 if there is a match or 0 otherwise.
static inline __attribute__((always_inline)) __s32 match_any(void *final, __s32 state_id)
{
	struct glob_bitmap *bitmap = 0;

	if (state_id == -1)
		return 0;

	bitmap = (struct glob_bitmap *)map_lookup_elem(final, &state_id);
	if (!bitmap)
		return 0;

	return 1;
}

// This checks 'state_id' against 'final' map to check if there is a match
// for the pattern with a specific 'value'. In that case, we care about which
// pattern matches.
//
// Returns 1 if there is a match or 0 otherwise.
static inline __attribute__((always_inline)) __s32 match_value(void *final, __s32 state_id, __s32 value)
{
	struct glob_bitmap *bitmap = 0;

	if (state_id == -1)
		return 0;

	bitmap = (struct glob_bitmap *)map_lookup_elem(final, &state_id);
	if (!bitmap)
		return 0;

	// to make the verifier happy
	asm volatile("%[value] &= %1;\n"
		     : [value] "+r"(value)
		     : "i"(POSSIBLE_MAX_VALUES_MASK));

	return bitmap_read(bitmap, value);
}

#endif /* __BPF_GLOB_H__ */
