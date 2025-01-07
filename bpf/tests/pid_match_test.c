// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

#include "vmlinux.h"
#include "compiler.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "process/retprobe_map.h"
#include "process/types/basic.h"
#include "process/pfilter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} test_filter_map SEC(".maps");

__attribute__((section("raw_tracepoint/test"), used)) int
test_pid_match()
{
	__u32 *f;
	int zero = 0, index = 0;
	struct pid_filter *pid;
	struct execve_map_value *enter;

	f = map_lookup_elem(&test_filter_map, &zero);
	if (!f)
		return 0;

	pid = (struct pid_filter *)((u64)f + index);
	index += sizeof(struct pid_filter);

	enter = map_lookup_elem(&execve_map, &zero);
	if (!enter)
		return 0;

	struct selector_filter sel = {
		.index = index,
		.ty = pid->op,
		.flags = pid->flags,
		.len = pid->len,
	};

	return selector_match(f, &sel, enter, NULL, &process_filter_pid);
}
