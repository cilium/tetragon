// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#define MAX_GLOB_INPUT_SIZE 1024
#include "bpf_glob_multi.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define MAX_PATH_SIZE 1024

struct str {
	char path[MAX_PATH_SIZE];
	__u32 len;
	__s32 val;
	__u64 res;
	__u64 dur;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct str);
	__uint(max_entries, 1);
} tg_string_map SEC(".maps");

static u8 __check_pattern(void *dfa, void *final, char *path, __u32 len, __s32 val)
{
	__s32 state_id = check_pattern(dfa, path, len);

	if (val == -1)
		return !match_any(final, state_id);
	else if (val == -2)
		return match_any(final, state_id);
	return match_value(&tg_glob_final, state_id, val);
}

__attribute__((section("raw_tracepoint/test"), used)) int test_glob(unsigned long long *ctx)
{
	struct str *s;
	u32 zero = 0;
	u64 beg = 0;

	s = map_lookup_elem(&tg_string_map, &zero);
	if (!s)
		return 0;

	beg = ktime_get_boot_ns();
	s->res = __check_pattern(&tg_glob_dfa, &tg_glob_final, s->path, s->len, s->val);
	s->dur = (ktime_get_boot_ns() - beg);

	return 0;
}
