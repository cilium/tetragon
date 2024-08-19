// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_LSM

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#ifdef __LARGE_MAP_KEYS
#include "bpf_lsm_ima.h"
#endif
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#include "generic_calls.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_generic_kprobe);
} process_call_heap SEC(".maps");

int generic_lsm_setup_event(void *ctx);
int generic_lsm_process_event(void *ctx);
int generic_lsm_process_filter(void *ctx);
int generic_lsm_filter_arg(void *ctx);
int generic_lsm_actions(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 13);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} lsm_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&generic_lsm_setup_event,
		[1] = (void *)&generic_lsm_process_event,
		[2] = (void *)&generic_lsm_process_filter,
		[3] = (void *)&generic_lsm_filter_arg,
		[4] = (void *)&generic_lsm_actions,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, __s32);
} override_tasks SEC(".maps");

struct filter_map_value {
	unsigned char buf[FILTER_SIZE];
};

/* Arrays of size 1 will be rewritten to direct loads in verifier */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct filter_map_value);
} filter_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event_config);
} config_map SEC(".maps");

#ifdef __LARGE_BPF_PROG
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");
#define data_heap_ptr &data_heap
#else
#define data_heap_ptr 0
#endif

static struct generic_maps maps = {
	.heap = (struct bpf_map_def *)&process_call_heap,
	.calls = (struct bpf_map_def *)&lsm_calls,
	.config = (struct bpf_map_def *)&config_map,
	.filter = (struct bpf_map_def *)&filter_map,
	.override = (struct bpf_map_def *)&override_tasks,
};

#define MAIN "lsm/generic_lsm_core"

__attribute__((section((MAIN)), used)) int
generic_lsm_event(struct pt_regs *ctx)
{
	return generic_start_process_filter(ctx, &maps);
}

__attribute__((section("lsm"), used)) int
generic_lsm_setup_event(void *ctx)
{
	return generic_process_event_and_setup(
		ctx, (struct bpf_map_def *)&process_call_heap,
		(struct bpf_map_def *)&lsm_calls,
		(struct bpf_map_def *)&config_map,
		(struct bpf_map_def *)data_heap_ptr);
}

__attribute__((section("lsm"), used)) int
generic_lsm_process_event(void *ctx)
{
	return generic_process_event(ctx,
				     (struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&lsm_calls,
				     (struct bpf_map_def *)&config_map,
				     (struct bpf_map_def *)data_heap_ptr);
}

__attribute__((section("lsm"), used)) int
generic_lsm_process_filter(void *ctx)
{
	int ret;

	ret = generic_process_filter((struct bpf_map_def *)&process_call_heap,
				     (struct bpf_map_def *)&filter_map);
	if (ret == PFILTER_CONTINUE)
		tail_call(ctx, &lsm_calls, TAIL_CALL_FILTER);
	else if (ret == PFILTER_ACCEPT)
		tail_call(ctx, &lsm_calls, 0);
	return PFILTER_REJECT;
}

__attribute__((section("lsm"), used)) int
generic_lsm_filter_arg(void *ctx)
{
	return filter_read_arg(ctx, (struct bpf_map_def *)&process_call_heap,
			       (struct bpf_map_def *)&filter_map,
			       (struct bpf_map_def *)&lsm_calls,
			       (struct bpf_map_def *)&config_map,
			       true);
}

__attribute__((section("lsm"), used)) int
generic_lsm_actions(void *ctx)
{
	bool postit = generic_actions(ctx, &maps);

	struct msg_generic_kprobe *e;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	e->lsm.post = postit;
#ifdef __LARGE_MAP_KEYS
	// Set dummy hash entry for ima program
	if (e && e->common.flags & MSG_COMMON_FLAG_IMA_HASH && e->lsm.post) {
		struct ima_hash hash;

		__u64 pid_tgid = get_current_pid_tgid();

		memset(&hash, 0, sizeof(struct ima_hash));
		hash.state = 1;
		map_update_elem(&ima_hash_map, &pid_tgid, &hash, BPF_ANY);
	}
#endif

	// If NoPost action is set, check for Override action here
	if (!e->lsm.post)
		return try_override(ctx, (struct bpf_map_def *)&override_tasks);

	return 0;
}
