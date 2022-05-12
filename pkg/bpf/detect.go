// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

/*
#cgo CFLAGS: -I ../../bpf/include -I ../../bpf/libbpf/ -I ../../bpf/lib/
#cgo LDFLAGS: -L../../lib -L/usr/local/lib -lbpf -lelf -lz

#include <unistd.h>
#include "libbpf.h"

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)	\
	((struct bpf_insn) {			\
		.code = CODE,			\
		.dst_reg = DST,			\
		.src_reg = SRC,			\
		.off = OFF,			\
		.imm = IMM })

#define BPF_MOV64_IMM(DST, IMM)				\
	((struct bpf_insn) {				\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,	\
		.dst_reg = DST,				\
		.src_reg = 0,				\
		.off   = 0,				\
		.imm   = IMM })

#ifndef BPF_FUNC_override_return
#define BPF_FUNC_override_return 58
#endif

bool detect_override_return_helper(bool verbose, int version)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_2, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_override_return),
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        };
	char buf[4096];
	int fd;

	buf[0] = 0x0;
	fd = bpf_load_program(BPF_PROG_TYPE_KPROBE, insns, 4, "GPL", version, buf, sizeof(buf));
	if (fd >= 0)
		close(fd);
	if (verbose && fd < 0)
		fprintf(stderr, "%s\n", buf);
	return fd >= 0 ? true : false;
}

*/
import "C"

import (
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
)

type Feature struct {
	initialized bool
	detected    bool
}

var (
	overrideHelper = Feature{false, false}
)

func HasOverrideHelper() bool {
	if overrideHelper.initialized {
		return overrideHelper.detected
	}

	__version, _, err := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	if err != nil {
		return false
	}

	version := C.int(kernels.FixKernelVersion(__version))
	verbose := C.bool(option.Config.Verbosity > 0)
	detected := C.detect_override_return_helper(verbose, version)

	overrideHelper.detected = bool(detected)
	overrideHelper.initialized = true
	return overrideHelper.detected
}
