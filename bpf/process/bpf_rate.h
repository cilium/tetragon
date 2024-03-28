// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __RATE_H__
#define __RATE_H__

#define CLOCK_MONOTONIC 1
#define NS		(1000ULL * 1000ULL * 1000UL)

#include "bpf_tracing.h"
#include "bpf_helpers.h"

struct cgroup_rate_key {
	__u64 cgroupid;
};

struct cgroup_rate_value {
	__u64 curr;
	__u64 prev;
	__u64 time;
	__u64 throttled;
};

struct cgroup_rate_options {
	__u64 interval;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 32768);
	__type(key, struct cgroup_rate_key);
	__type(value, struct cgroup_rate_value);
} cgroup_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cgroup_rate_options);
} cgroup_rate_options_map SEC(".maps");

static inline __attribute__((always_inline)) bool
cgroup_rate(__u64 cgroupid, __u64 time)
{
	struct cgroup_rate_options *options;
	struct cgroup_rate_key key = {
		.cgroupid = cgroupid,
	};
	struct cgroup_rate_value *value;
	__u64 delta, interval;
	__u32 zero = 0;

	options = map_lookup_elem(&cgroup_rate_options_map, &zero);
	if (!options)
		return true;

	interval = options->interval;

	value = map_lookup_elem(&cgroup_rate_map, &key);
	if (!value) {
		struct cgroup_rate_value new_value = {
			.time = (time / interval) * interval,
			.curr = 1,
		};

		map_update_elem(&cgroup_rate_map, &key, &new_value, 0);
		return true;
	}

	delta = time - value->time;
	if (delta > interval) {
		if (delta > 2 * interval) {
			value->prev = 0;
			value->time = (time / interval) * interval;
		} else {
			value->prev = value->curr;
			value->time += interval;
		}
		value->curr = 0;
	}

	value->curr++;
	return !value->throttled;
}

#endif /* __RATE_H__ */
