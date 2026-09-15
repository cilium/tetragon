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

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

#ifdef __V61_BPF_PROG
	if (!CONFIG(USE_PERF_RING_BUF))
		return event_execve_rb(ctx);
#endif

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve_event_init(ctx, event);

	if (execve_rate_check(ctx, event)) {
		uint64_t size = execve_finalize_event(ctx, event);

		event_output_metric(ctx, MSG_OP_EXECVE, event, size);
	}
	return 0;
}
