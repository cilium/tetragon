// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sys/unix"
)

type Feature struct {
	init     sync.Once
	detected bool
}

var (
	kprobeMulti         Feature
	uprobeMulti         Feature
	buildid             Feature
	modifyReturn        Feature
	modifyReturnSyscall Feature
)

func HasOverrideHelper() bool {
	return features.HaveProgramHelper(ebpf.Kprobe, asm.FnOverrideReturn) == nil
}

func HasSignalHelper() bool {
	return features.HaveProgramHelper(ebpf.Kprobe, asm.FnSendSignal) == nil
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

func detectUprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_upm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceUprobeMulti,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return false
	}
	if err != nil {
		return false
	}
	defer prog.Close()

	ex, err := link.OpenExecutable("/proc/self/exe")
	if err != nil {
		return false
	}

	// need cilium/ebp fix, can't pass just addresses without symbol
	um, err := ex.UprobeMulti(nil, prog, &link.UprobeMultiOptions{Addresses: []uint64{1}})
	if err != nil {
		return false
	}
	um.Close()
	return true
}

func HasUprobeMulti() bool {
	uprobeMulti.init.Do(func() {
		uprobeMulti.detected = detectUprobeMulti()
	})
	return uprobeMulti.detected
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

func detectModifyReturnSyscall() (bool, error) {
	sysGetcpu, err := arch.AddSyscallPrefix("sys_getcpu")
	if err != nil {
		return false, fmt.Errorf("failed to add arch specific syscall prefix: %w", err)
	}
	logger.GetLogger().Debugf("probing detectModifyReturnSyscall using %s", sysGetcpu)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_sys_fmod_ret",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachModifyReturn,
		AttachTo:   sysGetcpu,
		License:    "MIT",
	})
	if err != nil {
		return false, fmt.Errorf("failed to load: %w", err)
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false, fmt.Errorf("failed to attach: %w", err)
	}
	link.Close()
	return true, nil
}

func HasModifyReturn() bool {
	modifyReturn.init.Do(func() {
		modifyReturn.detected = detectModifyReturn()
	})
	return modifyReturn.detected
}

func HasModifyReturnSyscall() bool {
	modifyReturnSyscall.init.Do(func() {
		var err error
		modifyReturnSyscall.detected, err = detectModifyReturnSyscall()
		if err != nil {
			logger.GetLogger().WithError(err).Error("detect modify return syscall")
		}
	})
	return modifyReturnSyscall.detected
}

func HasProgramLargeSize() bool {
	return features.HaveLargeInstructions() == nil
}

func LogFeatures() string {
	return fmt.Sprintf("override_return: %t, buildid: %t, kprobe_multi: %t, uprobe_multi %t, fmodret: %t, fmodret_syscall: %t, signal: %t, large: %t",
		HasOverrideHelper(), HasBuildId(), HasKprobeMulti(), HasUprobeMulti(),
		HasModifyReturn(), HasModifyReturnSyscall(), HasSignalHelper(), HasProgramLargeSize())
}
