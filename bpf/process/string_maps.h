// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef STRING_MAPS_H__
#define STRING_MAPS_H__

#define STRING_MAPS_OUTER_MAX_ENTRIES 8

/*
 * To facilitate an arbitrary number of strings that can be matched on, string matching
 * uses a hash look up. The problem with this is that the key to a hash has to be a fixed
 * size, so if the maximum string length is 128 bytes, then all stored strings will be
 * 128 bytes long (padded with 0s) and the string to be looked up also has to be padded
 * with 0s to 128 bytes. This means that a short string will be hashed as if it is 128
 * bytes long.
 *
 * The BPF hash maps use jhash for key hashing. See include/linux/jhash.h. This requires
 * approximately 1 CPU cycle per byte, so in the example above, hashing every string,
 * regardless of length, will take ~128 cycles, which is clearly inefficient. See
 * https://fosdem.org/2023/schedule/event/bpf_hashing/ for details.
 *
 * jhash hashes in 12 byte blocks (3 x u32). For all lengths >12, a number of 12 byte
 * blocks are hashed, and the remainder is hashed using a combination of single byte
 * loads/shifts, followed by a final mix. It appears that the most efficient use of
 * jhash is with lengths equal to 12k + 1, minimising the number of single byte loads/
 * shifts.
 *
 * In order to reduce the amount of hashing of padded 0s, we opt to store string matches
 * in multiple hashes, with increasing key sizes, where the key size is one more than a
 * multiple of 12. Each string to be stored is placed in the hash that has the smallest
 * key size that can accommodate it (and is padded to the key size). Strings to be looked
 * up are equally padded to the smallest key size that can accommodate them, and then
 * looked up in the related map.
 *
 * The chosen key sizes are 25, 49, 73, 97, 121, 145 (6 maps).
 *
 * In order to distinguish between character buffers that end in 0s and similar buffers
 * that are padded with 0s, each string will be prefixed by its length stored in a
 * single byte.
 */
#define STRING_MAPS_KEY_INC_SIZE 24
#define STRING_MAPS_SIZE_0	 1 * STRING_MAPS_KEY_INC_SIZE + 1
#define STRING_MAPS_SIZE_1	 2 * STRING_MAPS_KEY_INC_SIZE + 1
#define STRING_MAPS_SIZE_2	 3 * STRING_MAPS_KEY_INC_SIZE + 1
#define STRING_MAPS_SIZE_3	 4 * STRING_MAPS_KEY_INC_SIZE + 1
#define STRING_MAPS_SIZE_4	 5 * STRING_MAPS_KEY_INC_SIZE + 1
#define STRING_MAPS_SIZE_5	 6 * STRING_MAPS_KEY_INC_SIZE + 1

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_0]);
			__type(value, __u8);
		});
} string_maps_0 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_1]);
			__type(value, __u8);
		});
} string_maps_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_2]);
			__type(value, __u8);
		});
} string_maps_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_3]);
			__type(value, __u8);
		});
} string_maps_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_4]);
			__type(value, __u8);
		});
} string_maps_4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[STRING_MAPS_SIZE_5]);
			__type(value, __u8);
		});
} string_maps_5 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 512);
} string_maps_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 512);
} string_maps_ro_zero SEC(".maps");

#define STRING_PREFIX_MAX_LENGTH 128

struct string_prefix_lpm_trie {
	__u32 prefixlen;
	__u8 data[STRING_PREFIX_MAX_LENGTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[sizeof(struct string_prefix_lpm_trie)]); // Need to specify as byte array as wouldn't take struct as key type
			__type(value, __u8);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} string_prefix_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct string_prefix_lpm_trie));
} string_prefix_maps_heap SEC(".maps");

#define STRING_POSTFIX_MAX_LENGTH 128
#define STRING_POSTFIX_MAX_MASK	  (STRING_POSTFIX_MAX_LENGTH - 1)
#ifdef __LARGE_BPF_PROG
#define STRING_POSTFIX_MAX_MATCH_LENGTH STRING_POSTFIX_MAX_LENGTH
#else
#define STRING_POSTFIX_MAX_MATCH_LENGTH 96
#endif

struct string_postfix_lpm_trie {
	__u32 prefixlen;
	__u8 data[STRING_POSTFIX_MAX_LENGTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, STRING_MAPS_OUTER_MAX_ENTRIES);
	__uint(key_size, sizeof(__u32));
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_LPM_TRIE);
			__uint(max_entries, 1);
			__type(key, __u8[sizeof(struct string_postfix_lpm_trie)]); // Need to specify as byte array as wouldn't take struct as key type
			__type(value, __u8);
			__uint(map_flags, BPF_F_NO_PREALLOC);
		});
} string_postfix_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct string_postfix_lpm_trie));
} string_postfix_maps_heap SEC(".maps");

#endif // STRING_MAPS_H__
