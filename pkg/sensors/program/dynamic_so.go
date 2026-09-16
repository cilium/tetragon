// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package program

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
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
	DlsymOff  uint64
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

func getProgName(sym string) string {
	return fmt.Sprintf("handle_%s_ret", sym)
}

func getPinName(sym string) string {
	return sym + "_ret"
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

func (dynOv *DynamicOverride) GetMaps(load *Program) []*Map {
	pendingCallsMap := MapBuilderProgram("pending_calls", load)
	resolvedCacheMap := MapBuilderProgram("resolved_cache", load)
	libcAddrsMap := MapBuilderProgram("libc_addrs_map", load)
	return []*Map{pendingCallsMap, resolvedCacheMap, libcAddrsMap}
}

func (dynOv *DynamicOverride) uprobeExtraAttach(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	attach uprobeAttachFunc) (unloader.Unloader, unloader.Unloader, unloader.Unloader, error) {
	var (
		dynOvUnloaders [3]unloader.Unloader
		err            error
	)

	// We need to override program attach data and force-set retprobe
	origAttachData := load.AttachData
	origLoadRetprobe := load.RetProbe
	defer func() {
		load.SetAttachData(origAttachData)
		load.SetRetProbe(origLoadRetprobe)
	}()
	load.SetRetProbe(true)

	// Check if we are in single or multi mode
	_, ok := load.AttachData.(*MultiUprobeAttachData)
	if ok {
		// Multi
		data := &MultiUprobeAttachData{}
		data.Attach = make(map[string]*MultiUprobeAttachSymbolsCookies)
		load.SetAttachData(data)
		for i, sym := range []string{mmapName, dlopenName} {
			cookies := MultiUprobeAttachSymbolsCookies{
				Symbols: []string{sym},
			}
			data.Attach[hostLibc] = &cookies
			if dynOvUnloaders[i], err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
				getProgName(sym), getPinName(sym), attach); err != nil {
				return dynOvUnloaders[0], dynOvUnloaders[1], dynOvUnloaders[2], err
			}
		}

	} else {
		attachData := UprobeAttachData{
			Path: hostLibc,
		}

		load.SetAttachData(&attachData)

		for i, sym := range []string{mmapName, dlopenName} {
			attachData.Symbol = sym
			if dynOvUnloaders[i], err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
				getProgName(sym), getPinName(sym), attach); err != nil {
				return dynOvUnloaders[0], dynOvUnloaders[1], dynOvUnloaders[2], err
			}
		}
	}

	return dynOvUnloaders[0], dynOvUnloaders[1], dynOvUnloaders[2], nil
}

func (dynOv *DynamicOverride) uprobeDisableExtraProgs(coll *ebpf.CollectionSpec) {
	// Note this is called with a NIL dynOv object; DO NOT dereference it.
	for _, sym := range []string{mmapName, dlopenName} {
		disableProg(coll, getProgName(sym))
	}
}
