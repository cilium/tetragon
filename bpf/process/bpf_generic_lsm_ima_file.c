// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#define GENERIC_LSM

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_lsm_ima.h"
#include "retprobe_map.h"
#include "types/basic.h"
#include "generic_maps.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

__attribute__((section("lsm.s/generic_lsm_ima_file"), used)) int
BPF_PROG(ima_file, struct file *file)
{
	struct ima_hash hash;
	__u64 pid_tgid = get_current_pid_tgid();
	struct ima_hash *dummy = map_lookup_elem(&ima_hash_map, &pid_tgid);

	if (dummy && dummy->state == 1) {
		if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ima_file_hash))
			hash.algo = ima_file_hash(file, &hash.value, MAX_IMA_HASH_SIZE);
		else
			hash.algo = ima_inode_hash(file->f_inode, &hash.value, MAX_IMA_HASH_SIZE);
		hash.state = 2;
		map_update_elem(&ima_hash_map, &pid_tgid, &hash, BPF_ANY);
	}
	return 0;
}
