// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "common.h"
#include "process.h"

struct update_data {
	__u32 pid;
	__u32 bit;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct update_data);
} execve_map_update_data SEC(".maps");

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

__attribute__((section("seccomp"), used)) int
execve_map_update(void *ctx)
{
	__u32 idx = 0, *data, pid, bit;
	struct execve_map_value *curr;

	data = map_lookup_elem(&execve_map_update_data, &idx);
	if (!data)
		return 0;

	pid = data[0];
	bit = data[1];

	bpf_printk("KRAVA pid %u bit %u\n", pid, bit);

	curr = execve_map_get_noinit(pid);
	if (curr) {
		bpf_printk("KRAVA found, unset\n");
		__sync_fetch_and_and(&curr->bin.mb_bitset, ~(1 << bit));
	} else {
		bpf_printk("KRAVA NOT found\n");
	}

	return 0;
}
