// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type Feature struct {
	init     sync.Once
	detected bool
}

var (
	overrideHelper   Feature
	signalHelper     Feature
	kprobeMulti      Feature
	buildid          Feature
	modifyReturn     Feature
	largeProgramSize Feature
)

func detectOverrideHelper() bool {
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
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

func HasOverrideHelper() bool {
	overrideHelper.init.Do(func() {
		overrideHelper.detected = detectOverrideHelper()
	})
	return overrideHelper.detected
}

func detectSignalHelper() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R2, 2, asm.DWord),
			asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Constant: 109},
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

func HasSignalHelper() bool {
	signalHelper.init.Do(func() {
		signalHelper.detected = detectSignalHelper()
	})
	return signalHelper.detected
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
	kprobeMulti.init.Do(func() {
		kprobeMulti.detected = detectKprobeMulti()
	})
	return kprobeMulti.detected
}

func detectBuildId() bool {
	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Bits:        unix.PerfBitWatermark | unix.PerfBitMmap | unix.PerfBitMmap2 | PerfBitBuildId,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      1,
	}

	attr.Size = uint32(unsafe.Sizeof(*attr))
	fd, err := unix.PerfEventOpen(attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err == nil {
		unix.Close(fd)
		return true
	}
	return false
}

func HasBuildId() bool {
	buildid.init.Do(func() {
		buildid.detected = detectBuildId()
	})
	return buildid.detected
}

func detectModifyReturn() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_fmod_ret",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachModifyReturn,
		License:    "MIT",
		AttachTo:   "security_task_prctl",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	link.Close()
	return true
}

func HasModifyReturn() bool {
	modifyReturn.init.Do(func() {
		modifyReturn.detected = detectModifyReturn()
	})
	return modifyReturn.detected
}

func detectLargeProgramSize() bool {
	insns := asm.Instructions{}

	for i := 0; i < 4096; i++ {
		insns = append(insns, asm.Mov.Imm(asm.R0, 1))
	}
	insns = append(insns, asm.Return())

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Kprobe,
		Instructions: insns,
		AttachType:   ebpf.AttachModifyReturn,
		License:      "MIT",
	})
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

func HasProgramLargeSize() bool {
	largeProgramSize.init.Do(func() {
		largeProgramSize.detected = detectLargeProgramSize()
	})
	return largeProgramSize.detected
}

func LogFeatures() string {
	return fmt.Sprintf("override_return: %t, buildid: %t, kprobe_multi: %t, fmodret: %t, signal: %t, large: %t",
		HasOverrideHelper(), HasBuildId(), HasKprobeMulti(), HasModifyReturn(), HasSignalHelper(), HasProgramLargeSize())
}
