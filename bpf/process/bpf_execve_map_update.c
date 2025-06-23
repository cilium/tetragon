// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "common.h"
#include "process.h"

struct update_data {
	__u32 bit;
	__u32 cnt;
	__u32 pids[1024];
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
	struct execve_map_value *curr;
	struct update_data * data;
	__u32 idx = 0, pid = 0;
        struct bpf_iter_num it;
        int *v;

	data = map_lookup_elem(&execve_map_update_data, &idx);
	if (!data)
		return 0;

	bpf_printk("KRAVA pid %u bit %u\n", data->bit, data->cnt);

        bpf_iter_num_new(&it, 0, 1000);
        for (v = bpf_iter_num_next(&it); v; v = bpf_iter_num_next(&it)) {
		__u32 idx = (__u32) *v;

		asm volatile("%[idx] &= 0x3ff;\n"
                             : [idx] "+r"(idx));

		pid = data->pids[idx];

		if (data->cnt == (__u32) *v)
			break;
		curr = execve_map_get_noinit(pid);
		if (curr) {
			bpf_printk("KRAVA found, unset\n");
			__sync_fetch_and_and(&curr->bin.mb_bitset, ~(1 << data->bit));
		} else {
			bpf_printk("KRAVA NOT found\n");
		}

        }
        bpf_iter_num_destroy(&it);

	return 0;
}
