// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#ifndef __TG_CGROUP_LOOKUP_H
#define __TG_CGROUP_LOOKUP_H

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"

#include "environ_conf.h"
#include "bpf_cgroup.h"
#include "process/policy_filter.h"

static inline __attribute__((always_inline)) int
__proc_do_cgroup(void *ctx, struct task_struct *p)
{
	__u32 error_flags;
	struct cgroup *cgrp;
	__u64 cgrpfs_magic = 0;
	struct tetragon_conf *conf;
	int zero = 0, subsys_idx = 0;
	__u64 cgid, nsid;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf) {
		/* Select which cgroup version */
		cgrpfs_magic = conf->cgrp_fs_magic;
		subsys_idx = conf->tg_cgrpv1_subsys_idx;
	}

	cgrp = get_task_cgroup(p, cgrpfs_magic, subsys_idx, &error_flags);
	if (!cgrp)
		return 0;

	cgid = get_cgroup_id(cgrp);
	nsid = tg_maybe_insert_nsmap(cgid);
	DEBUG("procfs cgroup mapping cgid=%d -> nsid=%d", cgid, nsid);

	return nsid;
}

#endif /* __TG_CGROUP_LOOKUP_H */
