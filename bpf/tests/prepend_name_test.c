// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

//go:build ignore

#include "vmlinux.h"

#include "compiler.h"
#include "bpf_tracing.h" // bpf_printk

#include "bpf_task.h"
#include "process/bpf_process_event.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#define TEST_MAX_BUF_LEN 4096
#define NAME_MAX	 255

struct test_prepend_name_state_map_value {
	char buf[TEST_MAX_BUF_LEN];
	u64 buflen;
	char dname[NAME_MAX];
	char pad;
	u32 dlen;
	u32 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct test_prepend_name_state_map_value);
} test_prepend_name_state_map SEC(".maps");

__attribute__((section("raw_tracepoint/test"), used)) int
test_prepend_name()
{
	struct test_prepend_name_state_map_value *ts;
	int zero = 0;

	ts = map_lookup_elem(&test_prepend_name_state_map, &zero);
	if (!ts)
		return 1;

	if (ts->buflen < 0 || ts->buflen > TEST_MAX_BUF_LEN)
		return 2;

	char *bufptr = ts->buf + ts->buflen;

	ts->dlen &= 255;

	int ret = prepend_name((char *)&ts->buf, &bufptr, (int *)&ts->buflen, ts->dname, ts->dlen);

	ts->offset = bufptr - (char *)&ts->buf;

	return ret;
}
