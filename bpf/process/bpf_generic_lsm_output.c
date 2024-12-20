// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_LSM

#include "compiler.h"
#include "bpf_event.h"
#ifdef __LARGE_MAP_KEYS
#include "bpf_lsm_ima.h"
#endif
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/basic.h"
#include "generic_maps.h"

#include "generic_maps.h"
#include "generic_calls.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

__attribute__((section("lsm/generic_lsm_output"), used)) int
generic_lsm_output(void *ctx)
{
	struct msg_generic_kprobe *e;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;
#ifdef __LARGE_MAP_KEYS
	if (e && e->common.flags & MSG_COMMON_FLAG_IMA_HASH) {
		__u64 pid_tgid = get_current_pid_tgid();
		struct ima_hash *hash = map_lookup_elem(&ima_hash_map, &pid_tgid);

		if (hash && hash->state == 2) {
			// Copy hash after all arguments
			if (e->common.size + sizeof(struct ima_hash) <= 16383) {
				probe_read(&e->args[e->common.size & 16383], sizeof(struct ima_hash), (char *)hash);
				e->common.size += sizeof(struct ima_hash);
			}
			map_delete_elem(&ima_hash_map, &pid_tgid);
		}
	}
#endif
	if (e->lsm.post)
		generic_output(ctx, MSG_OP_GENERIC_LSM);
	return try_override(ctx, (struct bpf_map_def *)&override_tasks);
}
