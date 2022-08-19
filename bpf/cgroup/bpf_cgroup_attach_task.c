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

/* This allows to discover Tetragon cgroup configurations */
__attribute__((section(("raw_tracepoint/cgroup_attach_task")), used)) int
tg_tp_cgrp_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
	int level, hierarchy_id, zero = 0;
	uint64_t cgrpid;
	uint32_t pid, tgid;
	struct cgroup *cgrp;
	struct tetragon_conf *config;
	struct cgroup_tracking_value *cgrp_heap;
	struct task_struct *task;
	struct execve_map_value *curr;

	/* TODO track tasks that are being attached here and put cgrp->state = CGROUP_RUNNING */

	config = map_lookup_elem(&tg_conf_map, &zero);
	if (!config)
		return 0;

	/* Tetragon cgroup level was already set let's exit */
	if (likely(config->tg_cgrp_level != 0))
		return 0;

	cgrp = (struct cgroup *)ctx->args[0];
	task = (struct task_struct *)ctx->args[2];

	pid = get_current_pid_tgid() >> 32;
	probe_read(&tgid, sizeof(tgid), _(&task->tgid));
	/* Check if it was migrating itself */
	if (likely(pid != tgid))
		return 0;

	cgrpid = get_cgroup_id(cgrp);
	hierarchy_id = get_cgroup_hierarchy_id(cgrp);

	/* Check if target Cgroup matches and it is same hierarchy ID */
	if (config->tg_cgrp_hierarchy != hierarchy_id || config->tg_cgrpid != cgrpid)
		return 0;

	/* Let's initialize tetragon itself in execve_value_map here */
	curr = execve_map_get(pid);
	if (curr)
		curr->cgrpid_tracker = cgrpid;

	level = get_cgroup_level(cgrp);
	/* Set level to max cgroup nested */
	if (level > CGROUP_MAX_NESTED_LEVEL) {
		level = CGROUP_MAX_NESTED_LEVEL;
		/* Fix up cgroup ID if we are bellow max nested hierarchies */
		cgrpid = get_ancestor_cgroup_id(cgrp, config->cgrp_fs_magic, level);
		config->tg_cgrpid = cgrpid;

		/* Update Tetragon own cgroup id if necessary */
		if (curr)
			curr->cgrpid_tracker = cgrpid;
	}

	/* Update config, pids are used for debugging */
	config->pid = pid;
	config->nspid = get_task_pid_vnr();
	config->tg_cgrp_level = level;

	/* Match later all cgroups level where tasks are being migrated to */
	if (config->tg_cgrp_level > 0 && level <= config->tg_cgrp_level) {
		/* Mark this cgroup as being RUNNING now */
		cgrp_heap = __init_cgrp_tracking_val_heap(cgrp, CGROUP_RUNNING);
		if (!cgrp_heap)
			return 0;

		/* If there was a previous matching entry let's overwrite it */
		map_update_elem(&tg_cgrps_tracking_map, &cgrpid, cgrp_heap,
				BPF_ANY);

		/* Todo: notify events only about cgroup being tracked or Tetragon self migration */
		send_cgrp_event(ctx, cgrp_heap, cgrpid,
				MSG_OP_CGROUP_ATTACH_TASK, EVENT_FORCE_SEND);
	}

	return 0;
}
