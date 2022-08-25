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

/* Remove tracked cgroups from bpf map */
__attribute__((section(("raw_tracepoint/cgroup_rmdir")), used)) int
tg_tp_cgrp_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
	uint64_t cgrpid;
	struct cgroup *cgrp;
	struct cgroup_tracking_value *cgrp_track;

	cgrp = (struct cgroup *)ctx->args[0];
	cgrpid = get_cgroup_id(cgrp);
	/* This should never happen */
	if (unlikely(cgrpid == 0))
		return 0;

	cgrp_track = map_lookup_elem(&tg_cgrps_tracking_map, &cgrpid);
	/* This was never tracked exit now */
	if (!cgrp_track)
		return 0;

	send_cgrp_event(ctx, cgrp_track, cgrpid, MSG_OP_CGROUP_RMDIR,
			EVENT_NOFORCE_SEND);

	map_delete_elem(&tg_cgrps_tracking_map, &cgrpid);

	return 0;
}
