// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPFATTR_H__
#define __BPFATTR_H__

#define BPF_OBJ_NAME_LEN 16U

struct bpf_info_type {
	__u32 prog_type;
	__u32 insn_cnt;
	char prog_name[BPF_OBJ_NAME_LEN];
};

#endif
