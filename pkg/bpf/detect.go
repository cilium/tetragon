// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type Feature struct {
	initialized bool
	detected    bool
}

var (
	overrideHelper = Feature{false, false}
	kprobeMulti    = Feature{false, false}
)

func HasOverrideHelper() bool {
	if overrideHelper.initialized {
		return overrideHelper.detected
	}
	overrideHelper.initialized = true
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R2, 2, asm.DWord),
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 58},
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	prog.Close()

	if err != nil {
		overrideHelper.detected = false
		return false
	}
	overrideHelper.detected = true
	return overrideHelper.detected
}

func detectKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_bpf_kprobe_multi_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	syms := []string{"vprintk"}
	opts := link.KprobeMultiOptions{Symbols: syms}

	_, err = link.KprobeMulti(prog, opts)
	return err == nil
}

func HasKprobeMulti() bool {
	if kprobeMulti.initialized {
		return kprobeMulti.detected
	}

	kprobeMulti.detected = detectKprobeMulti()
	kprobeMulti.initialized = true
	return kprobeMulti.detected
}
