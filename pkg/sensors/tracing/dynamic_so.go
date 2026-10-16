// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	mmapName   = "mmap"
	dlopenName = "dlopen"
	libcName   = "libc.so.6"
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
	offsets libcOffsets
}

func resolveDep(binaryPath, depName string) (string, error) {
	cmd := exec.Command("ldd", binaryPath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to trace dependencies for %q: %w", binaryPath, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// We don't handle direct paths like the interpreter: /lib64/ld-linux-x86-64.so.2 (0x000...)
		// or virtual DSOs like linux-vdso.so.1
		if line == "" || !strings.Contains(line, "=>") {
			continue
		}

		// Handle the standard format: libname.so.N => /path/to/lib.so.N (0x000...)
		if strings.Contains(line, "=>") {
			parts := strings.Split(line, "=>")
			libName := strings.TrimSpace(parts[0])
			if libName == depName {
				// The right side contains the path and the memory address
				rightSide := strings.TrimSpace(parts[1])
				pathParts := strings.Fields(rightSide)
				if len(pathParts) > 0 {
					libPath := pathParts[0]
					// Skip entries like "not found"
					if libPath != "not" {
						return libPath, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("failed to resolve dependency %q in binary %q", depName, binaryPath)
}

func (offsets *libcOffsets) load(binary string) error {
	hostLibc, err := resolveDep(binary, libcName)
	if err != nil {
		return err
	}
	f, err := elf.OpenSafeELFFile(hostLibc)
	if err != nil {
		return err
	}
	defer f.Close()

	if offsets.MmapOff, err = f.DynamicAddress(mmapName); err != nil {
		return err
	}
	if offsets.DlopenOff, err = f.DynamicAddress(dlopenName); err != nil {
		return err
	}
	return nil
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

func (dynOv *DynamicOverride) Init(act *v1alpha1.ActionSelector, binary string) error {
	if err := dynOv.offsets.load(binary); err != nil {
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

	// They will be adjusted to ASLR libc base address in the kernel
	uprobeRegs.MmapAddr = dynOv.offsets.MmapOff
	uprobeRegs.DlopenAddr = dynOv.offsets.DlopenOff
	return uprobeRegs
}

func (dynOv *DynamicOverride) GetMaps(load *program.Program) []*program.Map {
	pendingCallsMap := program.MapBuilderProgram("tg_dyn_sm", load)
	return []*program.Map{pendingCallsMap}
}
