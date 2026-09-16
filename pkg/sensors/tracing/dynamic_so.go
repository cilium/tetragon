// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	mmapName   = "mmap"
	dlopenName = "dlopen"
	hostLibcRe = "/usr/lib/*/libc.so.6"
)

var (
	hostLibc    string
	hostOffsets libcOffsets
)

// LibcOffsets holds symbol values relative to load bias (i.e., NOT yet
// adjusted for a specific process's ASLR base). These are stable for a
// given libc binary on disk, so we cache them by file identity.
type libcOffsets struct {
	MmapOff   uint64
	DlopenOff uint64
}

type DynamicOverride struct {
	Library string
	Addr    uint64
}

func getHostLibc() string {
	if hostLibc == "" {
		matches, _ := filepath.Glob(hostLibcRe)
		if len(matches) > 0 {
			hostLibc = matches[0]
		}
	}
	return hostLibc
}

func getHostOffsets() (*libcOffsets, error) {
	if hostOffsets.MmapOff == 0 {
		getHostLibc()
		if hostLibc == "" {
			return nil, errors.New("failed to find host libc but it is needed for dynamic SO loading")
		}
		f, err := elf.OpenSafeELFFile(hostLibc)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err = loadHostOffset(mmapName, f); err != nil {
			return nil, err
		}
		if err = loadHostOffset(dlopenName, f); err != nil {
			return nil, err
		}
	}
	return &hostOffsets, nil
}

func ValidateSODynamic(uprobe *v1alpha1.UProbeSpec) error {
	for _, s := range uprobe.Selectors {
		for _, action := range s.MatchActions {
			if action.Action != "Override" || action.ArgNewSymbol == "" || action.SoPath == "" {
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

			// Fetch host libc and resolve required symbols addresses.
			if _, err := getHostOffsets(); err != nil {
				return fmt.Errorf("uprobe Override dynamic SO feature requires host libc to be found: %w", err)
			}
		}
	}
	return nil
}

func IsSODynamic(selectors []v1alpha1.KProbeSelector) bool {
	for _, s := range selectors {
		for _, action := range s.MatchActions {
			if action.Action == "Override" {
				if action.ArgNewSymbol != "" && action.SoPath != "" {
					return true
				}
			}
		}
	}
	return false
}

func loadHostOffset(sym string, f *elf.SafeELFFile) error {
	var err error
	switch sym {
	case mmapName:
		if hostOffsets.MmapOff == 0 {
			hostOffsets.MmapOff, err = f.DynamicAddress(sym)
		}
	case dlopenName:
		if hostOffsets.DlopenOff == 0 {
			hostOffsets.DlopenOff, err = f.DynamicAddress(sym)
		}
	}
	return err
}

func (dynOv *DynamicOverride) Init(act *v1alpha1.ActionSelector) error {
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

	// They will be adjusted to ASLR libc base address in the kernel
	uprobeRegs.MmapAddr = hostOffsets.MmapOff
	uprobeRegs.DlopenAddr = hostOffsets.DlopenOff
	return uprobeRegs
}

func (dynOv *DynamicOverride) GetMaps(load *program.Program) []*program.Map {
	pendingCallsMap := program.MapBuilderProgram("tg_dyn_sm", load)
	return []*program.Map{pendingCallsMap}
}
