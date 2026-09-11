// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package program

import (
	"errors"
	"fmt"
	"os"
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
	dlsymName  = "dlsym"
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
	Symbol  string
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
		if err = loadHostOffset(dlsymName, f); err != nil {
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
			st, err := os.Stat(action.SoPath)
			if err != nil {
				return err
			}
			if st.IsDir() {
				return fmt.Errorf("uprobe Override action sopath %q is a directory", action.SoPath)
			}

			// Fetch host libc and resolve required symbols addresses.
			if _, err = getHostOffsets(); err != nil {
				return fmt.Errorf("uprobe Override dynamic SO feature requires host libc to be found: %w", err)
			}
		}
	}
	return nil
}

func IsSODynamic(uprobe *v1alpha1.UProbeSpec) bool {
	for _, s := range uprobe.Selectors {
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
	case dlsymName:
		if hostOffsets.DlsymOff == 0 {
			hostOffsets.DlsymOff, err = f.DynamicAddress(sym)
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

func (dynOv *DynamicOverride) PopulateUprobeRegs() processapi.UprobeRegs {
	uprobeRegs := processapi.UprobeRegs{}
	sopath := dynOv.Library + "\000"
	n := copy(uprobeRegs.Sopath[:], sopath)
	if n != len(sopath) {
		logger.GetLogger().Warn("register sopath count mismatch", "len sopath", len(sopath))
	}
	uprobeRegs.SopathLen = uint32(n)

	symbol := dynOv.Symbol + "\000"
	n = copy(uprobeRegs.Symbol[:], symbol)
	if n != len(symbol) {
		logger.GetLogger().Warn("register symbol count mismatch", "len symbol", len(symbol))
	}
	uprobeRegs.SymbolLen = uint32(n)

	// They will be adjusted to ASLR libc base address in the kernel
	uprobeRegs.DlopenAddr = hostOffsets.DlopenOff
	uprobeRegs.DlsymAddr = hostOffsets.DlsymOff
	uprobeRegs.MmapAddr = hostOffsets.MmapOff
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
		for i, sym := range []string{mmapName, dlopenName, dlsymName} {
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

		for i, sym := range []string{mmapName, dlopenName, dlsymName} {
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
	for _, sym := range []string{mmapName, dlopenName, dlsymName} {
		disableProg(coll, getProgName(sym))
	}
}
