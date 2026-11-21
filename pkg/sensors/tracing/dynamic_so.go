// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/elf/ldso"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	mmapName   = "mmap"
	dlopenName = "dlopen"
)

// libcInfo describes the libc used by the traced binary.
//
// Offsets are symbol values relative to load bias (i.e., NOT yet adjusted
// for a specific process's ASLR base). These are stable for a given libc
// binary on disk.
type libcInfo struct {
	// Name is the file name of the libc mapped in the process, used by the
	// bpf side to find the libc base address among the process mappings.
	Name      string
	MmapOff   uint64
	DlopenOff uint64
}

type DynamicOverride struct {
	Library string
	Addr    uint64
	libc    libcInfo
}

func (info *libcInfo) load(binary string) error {
	root := ldso.HostRoot()
	libcPath, libc, err := ldso.ResolveLibc(root, binary)
	if err != nil {
		return fmt.Errorf("failed to resolve libc: %w", err)
	}
	defer libc.Close()

	// The process mappings are named after the actual file, not after the
	// symlink we may have resolved.
	realPath, err := root.RealPath(libcPath)
	if err != nil {
		return fmt.Errorf("failed to resolve real path of %q: %w", libcPath, err)
	}
	info.Name = filepath.Base(realPath)
	// -1 to account for null terminator
	if len(info.Name) > processapi.SONAME_MAX-1 {
		return fmt.Errorf("libc file name %q exceeds maximum length of %d", info.Name, processapi.SONAME_MAX-1)
	}

	f, err := elf.NewSafeELFFile(libc)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %w", libcPath, err)
	}
	defer f.Close()

	if info.MmapOff, err = f.DynamicAddress(mmapName); err != nil {
		return fmt.Errorf("%q: %w", libcPath, err)
	}
	// dlopen moved from libdl into libc with glibc 2.34, while musl always
	// had it.
	if info.DlopenOff, err = f.DynamicAddress(dlopenName); err != nil {
		return fmt.Errorf("%q does not export %s (glibc < 2.34?): %w", libcPath, dlopenName, err)
	}
	return nil
}

func ValidateSODynamicMultiUprobeConsistency(uprobes []v1alpha1.UProbeSpec) error {
	// Each sopath selector of each uprobe takes a slot in the per-thread
	// state machine, which is shared by all the uprobes of a multi-uprobe sensor.
	numSoOverride := 0
	for _, curr := range uprobes {
		for _, s := range curr.Selectors {
			if slices.ContainsFunc(s.MatchActions, isSODynamicAction) {
				numSoOverride++
			}
		}
	}
	if numSoOverride > selectors.MaxSelectors {
		return fmt.Errorf("multi-uprobes mandate at most %d `sopath` selectors to be specified in the whole policy; found: %d", selectors.MaxSelectors, numSoOverride)
	}
	return nil
}

func ValidateSODynamic(uprobe *v1alpha1.UProbeSpec) error {
	for _, s := range uprobe.Selectors {
		for _, action := range s.MatchActions {
			if !isSODynamicAction(action) {
				continue
			}

			// -1 to account for null terminator
			if len(action.SoPath) > processapi.SOPATH_MAX-1 {
				return fmt.Errorf("sopath %q exceeds maximum length of %d", action.SoPath, processapi.SOPATH_MAX-1)
			}

			// -1 to account for null terminator
			if len(filepath.Base(action.SoPath)) > processapi.SONAME_MAX-1 {
				return fmt.Errorf("basename(sopath) %q exceeds maximum length of %d", action.SoPath, processapi.SONAME_MAX-1)
			}
		}
	}
	return nil
}

func isSODynamicAction(action v1alpha1.ActionSelector) bool {
	if action.Action == "Override" &&
		action.SoPath != "" &&
		(action.ArgNewSymbol != "" || action.ArgNewAddr != 0 || action.ArgNewOffset != 0) {
		return true
	}
	return false
}

func IsSODynamic(selectors []v1alpha1.KProbeSelector) bool {
	for _, s := range selectors {
		if slices.ContainsFunc(s.MatchActions, isSODynamicAction) {
			return true
		}
	}
	return false
}

func (dynOv *DynamicOverride) Init(act *v1alpha1.ActionSelector, binary string) error {
	if err := dynOv.libc.load(binary); err != nil {
		return err
	}

	dynOv.Library = act.SoPath
	f, err := elf.OpenSafeELFFile(dynOv.Library)
	if err != nil {
		return err
	}
	defer f.Close()
	switch {
	case act.ArgNewSymbol != "":
		dynOv.Addr, err = f.Address(act.ArgNewSymbol)
	case act.ArgNewAddr != 0:
		dynOv.Addr = act.ArgNewAddr
	case act.ArgNewOffset != 0:
		dynOv.Addr, err = f.AddrFromOffset(uint64(act.ArgNewOffset))
	}
	return err
}

func (dynOv *DynamicOverride) PopulateUprobeRegs() processapi.UprobeRegs {
	uprobeRegs := processapi.UprobeRegs{}
	sopath := dynOv.Library + "\000"
	n := copy(uprobeRegs.Sopath[:], sopath)
	if n != len(sopath) {
		logger.GetLogger().Warn("register sopath count mismatch", "len sopath", len(sopath))
	}
	uprobeRegs.SopathLen = uint32(n)

	soname := filepath.Base(dynOv.Library) + "\000"
	n = copy(uprobeRegs.SoName[:], soname)
	if n != len(soname) {
		logger.GetLogger().Warn("register soname count mismatch", "len soname", len(soname))
	}

	// This will be adjusted to so base address in the kernel
	uprobeRegs.SymAddr = dynOv.Addr

	libcFile := dynOv.libc.Name + "\000"
	n = copy(uprobeRegs.LibcName[:], libcFile)
	if n != len(libcFile) {
		logger.GetLogger().Warn("register libc name count mismatch", "len libc name", len(libcFile))
	}

	// They will be adjusted to ASLR libc base address in the kernel
	uprobeRegs.MmapAddr = dynOv.libc.MmapOff
	uprobeRegs.DlopenAddr = dynOv.libc.DlopenOff
	return uprobeRegs
}

func GetSODynamicMaps(load *program.Program) []*program.Map {
	pendingCallsMap := program.MapBuilderProgram("tg_dyn_sm", load)
	return []*program.Map{pendingCallsMap}
}
