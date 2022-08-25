// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type Feature struct {
	initialized bool
	detected    bool
}

var (
	overrideHelper = Feature{false, false}
	batchUpdate    = Feature{false, false}
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

func HasBatchUpdate() bool {
	if batchUpdate.initialized {
		return batchUpdate.detected
	}
	batchUpdate.initialized = true
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		return false
	}
	defer m.Close()

	var (
		keys   = []uint32{0, 1}
		values = []uint32{0, 1}
	)

	_, err = m.BatchUpdate(keys, values, nil)
	if err != nil {
		return false
	}
	batchUpdate.detected = true
	return batchUpdate.detected
}
