// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef _BPF_CGROUP_EVENTS__
#define _BPF_CGROUP_EVENTS__

#include "bpf_helpers.h"
#include "bpf_task.h"
#include "environ_conf.h"

/* This function will send the cgroup events to the ring buffer */
FUNC_INLINE int
send_cgrp_event(struct bpf_raw_tracepoint_args *ctx,
		struct cgroup_tracking_value *cgrp_track, __u64 cgrpid,
		__u32 op)
{
	pid_t pid;
	char *path;
	int zero = 0;
	uint64_t size;
	struct execve_map_value *curr;
	struct msg_cgroup_event *msg;

	msg = map_lookup_elem(&tg_cgrps_msg_heap, &zero);
	if (!msg)
		return 0;

	size = sizeof(struct msg_cgroup_event);
	msg->common.op = MSG_OP_CGROUP;
	msg->common.size = size;

	path = (char *)ctx->args[1];
	pid = (get_current_pid_tgid() >> 32);

	curr = execve_map_get_noinit(pid);
	if (curr) {
		msg->common.ktime = curr->key.ktime;
		msg->parent = curr->pkey;
		msg->flags = curr->flags;
		msg->ktime = curr->key.ktime;
	}
	msg->cgrp_op = op;
	msg->pid = pid;
	msg->nspid = get_task_pid_vnr_curr();
	msg->cgrpid = cgrpid;
	/* It is same as we are not tracking nested cgroups */
	msg->cgrpid_tracker = cgrpid;
	msg->cgrp_data.state = cgrp_track->state;
	msg->cgrp_data.level = cgrp_track->level;
	msg->cgrp_data.hierarchy_id = cgrp_track->hierarchy_id;
	memcpy(&msg->cgrp_data.name, &cgrp_track->name, KN_NAME_LENGTH);
	probe_read_str(&msg->path, PATH_MAP_SIZE - 1, path);

	perf_event_output_metric(ctx, MSG_OP_CGROUP, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);

	return 0;
}

#endif
