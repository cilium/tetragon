// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __BPF_LINUX_BINPRM_
#define __BPF_LINUX_BINPRM_

// Taken from bpf/process/types/basic.h
#define MAX_STRING 1024

struct msg_linux_binprm {
	char path[MAX_STRING];
} __attribute__((packed));

#endif
