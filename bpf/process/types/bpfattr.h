// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __BPFATTR_H__
#define __BPFATTR_H__

struct bpf_info_type {
	__u32 prog_type;
	__u32 insn_cnt;
	char prog_name[16U];
};

#endif
