// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_cgroup.h"
#include "bpf_rate.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

__attribute__((section(("raw_tracepoint/cgroup_rmdir")), used)) int
tg_cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];

	cgroup_rate_del(get_cgroup_id(cgrp));
	return 0;
}
