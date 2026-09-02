// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	mmapName   = "mmap"
	dlopenName = "dlopen"
	dlsymName  = "dlsym"
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

type dynamicOverride struct {
	library string
	symbol  string
}

func getHostLibc() string {
	if hostLibc == "" {
		hostLibcRe := "/usr/lib/*/libc.so.6"
		matches, _ := filepath.Glob(hostLibcRe)
		if len(matches) > 0 {
			hostLibc = matches[0]
		}
	}
	return hostLibc
}

func isSODynamic(uprobe *v1alpha1.UProbeSpec) bool {
	if !selectors.HasOverride(uprobe.Selectors) {
		return false
	}
	for _, s := range uprobe.Selectors {
		for _, action := range s.MatchActions {
			if action.Action == "Override" {
				if action.ArgNewSymbol != "" {
					_, _, ok := strings.Cut(action.ArgNewSymbol, ":")
					if ok {
						return true
					}
				}
			}
		}
	}
	return false
}

func initSODynamic(spec *v1alpha1.TracingPolicySpec, useMulti bool) error {
	for _, uprobe := range spec.UProbes {
		if isSODynamic(&uprobe) {
			// Very complex to support for uprobe multi
			// since we need to attach a non "generic_uprobe" program.
			if useMulti {
				return errors.New("dynamic SO loading does not work for multiuprobe; disable it with spec.options: [{name: disable-uprobe-multi, value: \"true\"}]")
			}
			hostLibcPath := getHostLibc()
			if hostLibcPath == "" {
				return errors.New("failed to find host libc but it is needed for dynamic SO loading")
			}
			spec.UProbes = append(spec.UProbes, v1alpha1.UProbeSpec{
				Path:    hostLibcPath,
				Symbols: []string{"mmap", "dlopen", "dlsym"},
			})
			break
		}
	}
	return nil
}

func loadHostOffset(sym string, f *elf.SafeELFFile) error {
	// Load libc mmap, dlopen and dlsym addresses!
	// Needed for dynamic SO loading.
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

func (g *genericUprobe) isDynOvLibc() bool {
	return g.targetPath == hostLibc && (g.symbol == mmapName || g.symbol == dlopenName || g.symbol == dlsymName)
}

func (g *genericUprobe) buildDynOvLibcProgram(loadProgName string) *program.Program {
	pinSymbol := fmt.Sprintf("handle_%s_ret", g.symbol)
	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		fmt.Sprintf("uretprobe/%s", g.symbol),
		fmt.Sprintf("uretprobe/%s", g.symbol),
		fmt.Sprintf("%d-%s", g.tableId.ID, pinSymbol),
		"generic_uprobe",
	).SetLoaderData(g).
		SetPolicy(g.policyName).SetRetProbe(true)
	return load
}

func (dynOv *dynamicOverride) populateUprobeRegs() processapi.UprobeRegs {
	uprobeRegs := processapi.UprobeRegs{}
	sopath := dynOv.library + "\000"
	n := copy(uprobeRegs.Sopath[:], sopath)
	if n != len(sopath) {
		logger.GetLogger().Warn("register sopath count mismatch", "len sopath", len(sopath))
	}
	uprobeRegs.SopathLen = uint32(n)

	symbol := dynOv.symbol + "\000"
	n = copy(uprobeRegs.Symbol[:], symbol)
	if n != len(symbol) {
		logger.GetLogger().Warn("register symbol count mismatch", "len symbol", len(symbol))
	}
	uprobeRegs.SymbolLen = uint32(n)

	// They will be adjusted to ASLR libc6 base address in the kernel
	uprobeRegs.DlopenAddr = hostOffsets.DlopenOff
	uprobeRegs.DlsymAddr = hostOffsets.DlsymOff
	uprobeRegs.MmapAddr = hostOffsets.MmapOff
	return uprobeRegs
}

func (dynOv *dynamicOverride) getMaps(load *program.Program) []*program.Map {
	pendingCallsMap := program.MapBuilder("pending_calls", load)
	resolvedCacheMap := program.MapBuilder("resolved_cache", load)
	return []*program.Map{pendingCallsMap, resolvedCacheMap}
}
