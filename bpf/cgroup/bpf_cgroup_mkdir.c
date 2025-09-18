// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_cgroup.h"
#include "bpf_task.h"
#include "bpf_cgroup_events.h"
#include "bpf_errmetrics.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

__attribute__((section(("raw_tracepoint/cgroup_mkdir")), used)) int
tg_tp_cgrp_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	uint64_t cgrpid;
	int level, hierarchy_id, zero = 0;
	struct cgroup *cgrp;
	struct cgroup_tracking_value *cgrp_heap;
	struct tetragon_conf *config;

	config = map_lookup_elem(&tg_conf_map, &zero);
	if (!config || config->tg_cgrp_level == 0)
		return 0;

	cgrp = (struct cgroup *)ctx->args[0];

	hierarchy_id = get_cgroup_hierarchy_id(cgrp);
	/*
	 * In a cgroupv1 setup, there can be multiple cgroup hierarchies but
	 * we want to track only one If this is not the hierarchy we care
	 * about, exit.
	 */
	if (config->tg_cgrp_hierarchy != hierarchy_id)
		return 0;

	level = get_cgroup_level(cgrp);
	/* This should never happen as the cgroup hierarchy has already been
	 * set (e.g., by systemd)
	 */
	if (level == 0)
		return 0;

	cgrpid = get_cgroup_id(cgrp);
	/* This should never happen unless the bpf helper failed */
	if (cgrpid == 0)
		return 0;

	/* We want to track all processes of a container system so that we can
	 * provide proper identity to events. To do that, we use a certain cgroup
	 * level. Any cgroups that are created under that level, we ignore.
	 * That is, if we are monitoring level 5, we do not care about cgroup
	 * events with level >5.
	 */
	if (level <= config->tg_cgrp_level) {
		cgrp_heap = __init_cgrp_tracking_val_heap(cgrp, CGROUP_NEW);
		if (!cgrp_heap)
			return 0;

		/* We track only for now cgroups that are at same or above tetragon
		 * level (ancestors level)
		 */
		with_errmetrics(map_update_elem, &tg_cgrps_tracking_map, &cgrpid, cgrp_heap,
				BPF_ANY);

		/* We forward bpf events only under TraceLevel */
		if (unlikely(config->loglevel == LOG_TRACE_LEVEL))
			send_cgrp_event(ctx, cgrp_heap, cgrpid,
					MSG_OP_CGROUP_MKDIR);
	}

	return 0;
}
