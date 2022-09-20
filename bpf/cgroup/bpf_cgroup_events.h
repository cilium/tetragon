// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef _BPF_CGROUP_EVENTS__
#define _BPF_CGROUP_EVENTS__

#include "bpf_helpers.h"
#include "bpf_events.h"
#include "environ_conf.h"

#define EVENT_NOFORCE_SEND 0
#define EVENT_FORCE_SEND   1

/* This function will send the cgroup events to the ring buffer
 * if Tetragon is running with log level set to LOG_TRACE_LEVEL.
 * If the parameter force is set to EVENT_FORCE_SEND, then the
 * event will be forwarded reguardless of the log level.
 */
static inline __attribute__((always_inline)) int
send_cgrp_event(struct bpf_raw_tracepoint_args *ctx,
		struct cgroup_tracking_value *cgrp_track, __u64 cgrpid,
		__u32 op, bool force)
{
	pid_t pid;
	char *path;
	int zero = 0;
	uint64_t size;
	struct task_struct *task;
	struct execve_map_value *curr;
	struct msg_cgroup_event *msg;
	struct tetragon_conf *config;

	/* First check if this message must be sent or not */
	if (likely(force == EVENT_NOFORCE_SEND)) {
		config = map_lookup_elem(&tg_conf_map, &zero);
		if (!config)
			return 0;

		/* We forward bpf events only under TraceLevel */
		if (likely(config->loglevel != LOG_TRACE_LEVEL))
			return 0;
	}

	msg = map_lookup_elem(&tg_cgrps_msg_heap, &zero);
	if (!msg)
		return 0;

	size = sizeof(struct msg_cgroup_event);
	msg->common.op = MSG_OP_CGROUP;
	msg->common.size = size;

	path = (char *)ctx->args[1];
	task = (struct task_struct *)get_current_task();
	probe_read(&pid, sizeof(pid), _(&task->tgid));

	curr = execve_map_get(pid);
	if (curr) {
		msg->common.ktime = curr->key.ktime;
		msg->parent = curr->pkey;
		msg->flags = curr->flags;
		msg->ktime = curr->key.ktime;
	}
	msg->cgrp_op = op;
	msg->pid = pid;
	msg->nspid = get_task_pid_vnr();
	msg->cgrpid = cgrpid;
	/* It is same as we are not tracking nested cgroups */
	msg->cgrpid_tracker = cgrpid;
	msg->cgrp_data.state = cgrp_track->state;
	msg->cgrp_data.level = cgrp_track->level;
	msg->cgrp_data.hierarchy_id = cgrp_track->hierarchy_id;
	memcpy(&msg->cgrp_data.name, &cgrp_track->name, KN_NAME_LENGTH);
	probe_read_str(&msg->path, PATH_MAP_SIZE - 1, path);

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);

	return 0;
}

#endif
