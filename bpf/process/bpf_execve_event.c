// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_execve_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "errmetrics.h"
#include "bpf_mbset.h"
#include "bpf_ktime.h"
#include "environ_conf.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#ifndef OVERRIDE_TAILCALL
int execve_rate(void *ctx);
int execve_send(struct bpf_raw_tracepoint_args *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__array(values, int(void *));
} execve_calls SEC(".maps") = {
	.values = {
		[0] = (void *)&execve_rate,
		[1] = (void *)&execve_send,
	},
};
#endif

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve_event_init(ctx, event);

	tail_call(ctx, &execve_calls, 0);
	return 0;
}

__attribute__((section("raw_tracepoint"), used)) int
execve_rate(void *ctx __arg_ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	if (execve_rate_check(ctx, event))
		tail_call(ctx, &execve_calls, 1);
	return 0;
}

__attribute__((section("raw_tracepoint"), used)) int
execve_send(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	return execve_send_event(ctx, event);
}
