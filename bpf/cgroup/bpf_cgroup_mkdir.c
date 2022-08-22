// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_cgroup.h"
#include "bpf_events.h"
#include "bpf_cgroup_events.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("raw_tracepoint/cgroup_mkdir")), used)) int
tg_tp_cgrp_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	pid_t pid;
	int level, zero = 0;
	uint64_t cgrpid;
	struct cgroup *cgrp;
	struct cgroup_tracking_value *cgrp_heap;
	struct tetragon_conf *config;
	struct task_struct *task;

	config = map_lookup_elem(&tg_conf_map, &zero);
	if (!config || config->tg_cgrp_level == 0)
		return 0;

	cgrp = (struct cgroup *)ctx->args[0];

	task = (struct task_struct *)get_current_task();
	probe_read(&pid, sizeof(pid), _(&task->tgid));
	cgrpid = get_cgroup_id(cgrp);
	level = get_cgroup_level(cgrp);

	if (level <= config->tg_cgrp_level) {
		cgrp_heap = __init_cgrp_tracking_val_heap(cgrp, CGROUP_NEW);
		if (!cgrp_heap)
			return 0;

		/* We track only for now cgroups that are at same or above tetragon level */
		map_update_elem(&tg_cgrps_tracking_map, &cgrpid, cgrp_heap,
				BPF_ANY);

		/* Notify events only about cgroup being tracked */
		send_cgrp_event(ctx, cgrp_heap, cgrpid, MSG_OP_CGROUP_MKDIR,
				EVENT_NOFORCE_SEND);
	}

	return 0;
}
