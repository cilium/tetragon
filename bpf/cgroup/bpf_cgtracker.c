// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_helpers.h"
#include "bpf_cgroup.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
#ifdef VMLINUX_KERNEL_VERSION
int _version __attribute__((section(("version")), used)) =
	VMLINUX_KERNEL_VERSION;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64); /* cgroup id */
	__type(value, __u64); /* tracker cgroup id */
} tg_cgtracker_map SEC(".maps");

/* new kernel cgroup definition */
struct cgroup___new {
	int level;
	struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

FUNC_INLINE __u64 cgroup_get_parent_id(struct cgroup *cgrp)
{
	struct cgroup___new *cgrp_new = (struct cgroup___new *)cgrp;

	// for newer kernels, we can access use ->ancestors to retrieve the parent
	if (bpf_core_field_exists(cgrp_new->ancestors)) {
		int level = get_cgroup_level(cgrp);

		if (level <= 0)
			return 0;
		return BPF_CORE_READ(cgrp_new, ancestors[level - 1], kn, id);
	}

	// otherwise, go over the parent pointer
	struct cgroup_subsys_state *parent_css = BPF_CORE_READ(cgrp, self.parent);

	if (parent_css) {
		struct cgroup *parent = container_of(parent_css, struct cgroup, self);
		__u64 parent_cgid = get_cgroup_id(parent);
		return parent_cgid;
	}

	return 0;
}

__attribute__((section(("raw_tracepoint/cgroup_mkdir")), used)) int
tg_cgtracker_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cgrp;
	__u64 cgid, cgid_parent, *cgid_tracker;

	cgrp = (struct cgroup *)ctx->args[0];
	cgid = get_cgroup_id(cgrp);
	if (cgid == 0)
		return 0;
	cgid_parent = cgroup_get_parent_id(cgrp);
	if (cgid_parent == 0)
		return 0;
	cgid_tracker = map_lookup_elem(&tg_cgtracker_map, &cgid_parent);
	if (cgid_tracker)
		map_update_elem(&tg_cgtracker_map, &cgid, cgid_tracker, BPF_ANY);

	return 0;
}

__attribute__((section(("raw_tracepoint/cgroup_release")), used)) int
tg_cgtracker_cgroup_release(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cgrp;
	__u64 cgid;

	cgrp = (struct cgroup *)ctx->args[0];
	cgid = get_cgroup_id(cgrp);
	if (cgid)
		map_delete_elem(&tg_cgtracker_map, &cgid);

	return 0;
}
