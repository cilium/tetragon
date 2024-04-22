// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ebtf "github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sys/unix"
)

type Feature struct {
	init     sync.Once
	detected bool
}

var (
	kprobeMulti            Feature
	uprobeMulti            Feature
	buildid                Feature
	modifyReturn           Feature
	modifyReturnSyscall    Feature
	linkPin                Feature
	lsm                    Feature
	missedStatsKprobe      Feature
	missedStatsKprobeMulti Feature
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

func detectLSM() bool {
	if features.HaveProgramType(ebpf.LSM) != nil {
		return false
	}
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		logger.GetLogger().WithError(err).Error("failed to read /sys/kernel/security/lsm")
		return false
	}
	if strings.Contains(string(b), "bpf") {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name: "probe_lsm_file_open",
			Type: ebpf.LSM,
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R0, 0),
				asm.Return(),
			},
			AttachTo:   "file_open",
			AttachType: ebpf.AttachLSMMac,
			License:    "Dual BSD/GPL",
		})
		if err != nil {
			logger.GetLogger().WithError(err).Error("failed to load lsm probe")
			return false
		}
		defer prog.Close()

		link, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			logger.GetLogger().WithError(err).Error("failed to attach lsm probe")
			return false
		}
		link.Close()
		return true
	}

	return false
}

func HasLSMPrograms() bool {
	lsm.init.Do(func() {
		lsm.detected = detectLSM()
	})
	return lsm.detected
}

func detectLinkPin() (bool, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_bpf_kprobe",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		return false, err
	}
	defer prog.Close()

	lnk, err := link.Kprobe("vprintk", prog, nil)
	if err != nil {
		return false, err
	}
	defer lnk.Close()

	if err := lnk.Pin(filepath.Join(GetMapRoot(), "test-link")); err != nil {
		return false, err
	}
	lnk.Unpin()
	return true, nil
}

func HasLinkPin() bool {
	linkPin.init.Do(func() {
		var err error

		linkPin.detected, err = detectLinkPin()
		if err != nil {
			logger.GetLogger().WithError(err).Error("detect link pin")
		}
	})
	return linkPin.detected
}

func detectMissedStats() (bool, bool) {
	spec, err := btf.NewBTF()
	if err != nil {
		return false, false
	}

	// bpf_link_info
	var linkInfo *ebtf.Struct
	if err := spec.TypeByName("bpf_link_info", &linkInfo); err != nil {
		return false, false
	}

	if len(linkInfo.Members) < 4 {
		return false, false
	}

	// bpf_link_info::union
	m := linkInfo.Members[3]
	union, ok := m.Type.(*ebtf.Union)
	if !ok {
		return false, false
	}

	kprobe := false
	kprobeMulti := false

	hasField := func(st *ebtf.Struct, name string) bool {
		for _, m := range st.Members {
			if m.Name == name {
				return true
			}
		}
		return false
	}

	detectKprobeMulti := func(m ebtf.Member) bool {
		// bpf_link_info::kprobe_multi
		st, ok := m.Type.(*ebtf.Struct)
		if !ok {
			return false
		}
		// bpf_link_info::kprobe_multi::missed
		return hasField(st, "missed")
	}

	detectKprobe := func(m ebtf.Member) bool {
		// bpf_link_info::perf_event
		st, ok := m.Type.(*ebtf.Struct)
		if !ok {
			return false
		}

		if len(st.Members) < 2 {
			return false
		}

		// bpf_link_info::perf_event::union
		tm := st.Members[1]
		un, ok := tm.Type.(*ebtf.Union)
		if !ok {
			return false
		}

		for _, mu := range un.Members {
			// bpf_link_info::perf_event::kprobe
			if mu.Name == "kprobe" {
				st2, ok := mu.Type.(*ebtf.Struct)
				if !ok {
					return false
				}
				// bpf_link_info::perf_event::kprobe::missed
				return hasField(st2, "missed")
			}
		}
		return false
	}

	for _, m := range union.Members {
		if m.Name == "kprobe_multi" {
			kprobeMulti = detectKprobeMulti(m)
		} else if m.Name == "perf_event" {
			kprobe = detectKprobe(m)
		}
	}

	return kprobe, kprobeMulti
}

func detectMissedStatsOnce() {
	missedStatsKprobe.init.Do(func() {
		kprobe, kprobeMulti := detectMissedStats()
		missedStatsKprobe.detected = kprobe
		missedStatsKprobeMulti.detected = kprobeMulti
	})
}

func HasMissedStatsPerfEvent() bool {
	detectMissedStatsOnce()
	return missedStatsKprobe.detected
}

func HasMissedStatsKprobeMulti() bool {
	detectMissedStatsOnce()
	return missedStatsKprobeMulti.detected
}

func LogFeatures() string {
	return fmt.Sprintf("override_return: %t, buildid: %t, kprobe_multi: %t, uprobe_multi %t, fmodret: %t, fmodret_syscall: %t, signal: %t, large: %t, link_pin: %t, lsm: %t, missed_stats_kprobe_multi: %t, missed_stats_kprobe: %t",
		HasOverrideHelper(), HasBuildId(), HasKprobeMulti(), HasUprobeMulti(),
		HasModifyReturn(), HasModifyReturnSyscall(), HasSignalHelper(), HasProgramLargeSize(),
		HasLinkPin(), HasLSMPrograms(), HasMissedStatsKprobeMulti(), HasMissedStatsPerfEvent())
}
