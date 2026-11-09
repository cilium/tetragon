// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __MULTI_KPROBE_MAPS_H__
#define __MULTI_KPROBE_MAPS_H__

#include "errno.h"

/* Generic kprobe multi always shares programs across policies. SHARED_KPROBE
 * selects its map layout, not an additional attachment mode. Uprobes and
 * enforcers also use __MULTI_KPROBE, but retain their own map layout.
 */
#if defined(__MULTI_KPROBE) && (defined(GENERIC_KPROBE) || defined(GENERIC_KRETPROBE))
#define SHARED_KPROBE

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} multi_scope SEC(".maps");

FUNC_INLINE bool multi_kprobe_setup(void *ctx)
{
	__u32 zero = 0, *scope = map_lookup_elem(&multi_scope, &zero);

	if (!scope)
		return false;
	*scope = get_attach_cookie(ctx) >> 32;
	return true;
}

FUNC_INLINE __u32 multi_kprobe_scope(void)
{
	__u32 zero = 0, *scope = map_lookup_elem(&multi_scope, &zero);

	return scope ? *scope : 0;
}

/* Selector maps already contain maps, so another level of map-in-map is
 * impossible. Namespace their local keys with the attachment's scope instead.
 */
#define MULTI_OUTER_TYPE BPF_MAP_TYPE_HASH_OF_MAPS
#define MULTI_KEY_TYPE	 __u64

FUNC_INLINE void *multi_lookup(void *map, const __u32 *key)
{
	__u64 scoped_key = ((__u64)multi_kprobe_scope() << 32) | *key;

	return map_lookup_elem(map, &scoped_key);
}

/* Mutable policy maps stay pinned at their existing paths. The shared
 * programs select the policy's map through these registries.
 * Use sizes for the inner template: clang can emit only forward BTF
 * declarations for struct types referenced through a nested anonymous map.
 */
#define POLICY_KEY(type)   __uint(key_size, sizeof(type))
#define POLICY_VALUE(type) __uint(value_size, sizeof(type))
#define POLICY_ARRAY_FLAGS BPF_F_INNER_MAP

#define POLICY_MAP(name, ...)                            \
	struct {                                         \
		__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS); \
		__uint(max_entries, 1024);               \
		__type(key, __u32);                      \
		__array(values, struct { __VA_ARGS__ }); \
	} name SEC(".maps")

FUNC_INLINE void *policy_map(void *map)
{
	__u32 scope = multi_kprobe_scope();

	return map_lookup_elem(map, &scope);
}

FUNC_INLINE void *policy_lookup(void *map, const void *key)
{
	void *inner = policy_map(map);

	return inner ? map_lookup_elem(inner, key) : 0;
}

FUNC_INLINE long policy_update(void *map, const void *key, const void *value, __u64 flags)
{
	void *inner = policy_map(map);

	return inner ? map_update_elem(inner, key, value, flags) : -ENOENT;
}

FUNC_INLINE long policy_delete(void *map, const void *key)
{
	void *inner = policy_map(map);

	return inner ? map_delete_elem(inner, key) : -ENOENT;
}

FUNC_INLINE long policy_stackid(void *ctx, void *map, __u64 flags)
{
	void *inner = policy_map(map);

	return inner ? get_stackid(ctx, inner, flags) : -ENOENT;
}

#else
#define MULTI_OUTER_TYPE   BPF_MAP_TYPE_ARRAY_OF_MAPS
#define MULTI_KEY_TYPE	   __u32
#define multi_lookup	   map_lookup_elem
#define policy_lookup	   map_lookup_elem
#define policy_update	   map_update_elem
#define policy_delete	   map_delete_elem
#define policy_stackid	   get_stackid
#define POLICY_KEY(type)   __type(key, type)
#define POLICY_VALUE(type) __type(value, type)
#define POLICY_ARRAY_FLAGS 0
#define POLICY_MAP(name, ...) \
	struct {              \
		__VA_ARGS__   \
	} name SEC(".maps")
#endif

#endif /* __MULTI_KPROBE_MAPS_H__ */
