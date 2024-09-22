// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "compiler.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, unsigned long);
} m1 SEC(".maps");

__attribute__((section("kprobe/wake_up_new_task"), used)) int
BPF_KPROBE(p2)
{
	map_lookup_elem(&m1, &(unsigned long){ 0 });
	return 0;
}
