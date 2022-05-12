// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	tetragonCgroupPath = "/run/tetragon/cgroup2"

	verifierLogBufferSize = 10 * 1024 * 1024 // 10MB
)

var (
	tetragonCgroupFD = -1
)

type Selector struct {
	MapName   string
	Selectors [128]byte
}

func LoadSockOpt(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
) error {
	return LoadCgroupProgram(bpfDir, mapDir, ciliumDir, load)
}

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Program, *ebpf.ProgramSpec) (Unloader, error)

func rawAttach(targetFD int) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (Unloader, error) {
		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  targetFD,
			Program: prog,
			Attach:  spec.AttachType,
		})
		if err != nil {
			prog.Close()
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return chainUnloader{
			pinUnloader{prog},
			&rawDetachUnloader{
				targetFD:   targetFD,
				name:       spec.Name,
				prog:       prog,
				attachType: spec.AttachType,
			},
		}, nil
	}
}

func LoadSkProgram(
	bpfDir, mapDir string,
	load *Program,
	targetSockmap *Map,
) error {

	if targetSockmap.mapHandle == nil {
		return fmt.Errorf("target map %s is not loaded", targetSockmap.Name)
	}

	return loadProgram(bpfDir, []string{mapDir}, load, rawAttach(targetSockmap.mapHandle.FD()))
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	selectors [128]byte,
) error {
	attach := func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (Unloader, error) {
		attachLinks, err := getDefaultRouteLinks()
		if err != nil {
			return nil, err
		}
		var unloader tcUnloader
		for _, link := range attachLinks {
			// NOTE: Set outer 'err' and break on error to rewind.
			logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
			isIngress := "tc_ingress" == load.Type
			if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
				break
			}
			if err = bpf.AttachTCIngress(prog.FD(), link.Attrs().Name, isIngress); err != nil {
				break
			}
			unloader.attachments = append(unloader.attachments, tcAttachment{link.Attrs().Name, isIngress})
		}
		if err != nil {
			if unloadErr := unloader.Unload(); unloadErr != nil {
				logger.GetLogger().Warnf("Failed to unload on TC program rewind: %s", unloadErr)
			}
			return nil, err
		}
		return unloader, nil
	}
	return loadProgram(bpfDir, []string{mapDir, ciliumDir}, load, attach)
}

func getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list selectored routes")
		return nil, err
	}
	allLinks, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list links")
		return nil, err
	}
	for _, route := range routes {
		for _, link := range allLinks {
			if link.Attrs().Index == route.LinkIndex {
				links = append(links, link)
			}
		}
	}
	return links, nil
}

func LoadCgroupProgram(
	bpfDir, mapDir, ciliumDir string,
	load *Program) error {
	if tetragonCgroupFD < 0 {
		fd, err := unix.Open(tetragonCgroupPath, unix.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("failed to open '%s': %w", tetragonCgroupPath, err)
		}
		tetragonCgroupFD = fd
	}
	return loadProgram(bpfDir, []string{mapDir, ciliumDir}, load, rawAttach(tetragonCgroupFD))
}

func installTailCalls(mapDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection) error {
	// FIXME(JM): This should be replaced by using the cilium/ebpf prog array initialization.

	secToProgName := make(map[string]string)
	for name, prog := range spec.Programs {
		secToProgName[prog.SectionName] = name
	}

	install := func(mapName string, secPrefix string) error {
		tailCallsMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
		if err != nil {
			return nil
		}
		defer tailCallsMap.Close()

		for i := 0; i < 6; i++ {
			secName := fmt.Sprintf("%s/%d", secPrefix, i)
			if progName, ok := secToProgName[secName]; ok {
				if prog, ok := coll.Programs[progName]; ok {
					err := tailCallsMap.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny)
					if err != nil {
						return fmt.Errorf("update of tail-call map '%s' failed: %w", mapName, err)
					}
				}
			}
		}
		return nil
	}

	if err := install("http1_calls", "sk_msg"); err != nil {
		return err
	}
	if err := install("http1_calls_skb", "sk_skb/stream_verdict"); err != nil {
		return err
	}
	if err := install("tls_calls", "classifier"); err != nil {
		return err
	}

	return nil
}

func SetFilter(mapDir string, mapName string, selectors [128]byte) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	return selectorMap.Update(uint32(0), selectors, ebpf.UpdateAny)
}

func slimVerifierError(errStr string) string {
	// The error is potentially up to 'verifierLogBufferSize' bytes long,
	// and most of it is not interesting. For a user-friendly output, we'll
	// only keep the first and last N lines.

	nLines := 30
	headLines := 0
	headEnd := 0

	for ; headEnd < len(errStr); headEnd++ {
		c := errStr[headEnd]
		if c == '\n' {
			headLines++
			if headLines >= nLines {
				break
			}
		}
	}

	tailStart := len(errStr) - 1
	tailLines := 0
	for ; tailStart > headEnd; tailStart-- {
		c := errStr[tailStart]
		if c == '\n' {
			tailLines++
			if tailLines >= nLines {
				tailStart++
				break
			}
		}
	}

	return errStr[:headEnd] + "\n...\n" + errStr[tailStart:]
}

func loadProgram(
	bpfDir string,
	mapDirs []string,
	load *Program,
	withProgram AttachFunc,
) error {
	var btfFile *os.File
	if btfFilePath := btf.GetCachedBTFFile(); btfFilePath != "/sys/kernel/btf/vmlinux" {
		// Non-standard path to BTF, open it and provide it as 'TargetBTF'.
		var err error
		btfFile, err = os.Open(btfFilePath)
		if err != nil {
			return fmt.Errorf("opening BTF file '%s' failed: %w", btfFilePath, err)
		}
		defer btfFile.Close()
	}

	spec, err := ebpf.LoadCollectionSpec(load.Name)
	if err != nil {
		return fmt.Errorf("loading collection spec failed: %w", err)
	}

	var progSpec *ebpf.ProgramSpec

	// Find the program spec for the target program
	for _, prog := range spec.Programs {
		if prog.SectionName == load.Label {
			progSpec = prog
			break
		}
	}

	if progSpec == nil {
		return fmt.Errorf("program for section '%s' not found", load.Label)
	}

	// Find all the maps referenced by the program, so we'll rewrite only
	// the ones used.
	refMaps := make(map[string]bool)
	for _, inst := range progSpec.Instructions {
		if inst.Reference != "" {
			refMaps[inst.Reference] = true
		}
	}

	pinnedMaps := make(map[string]*ebpf.Map)
	for name := range refMaps {
		var m *ebpf.Map
		var err error
		for _, mapDir := range mapDirs {
			mapPath := filepath.Join(mapDir, name)
			m, err = ebpf.LoadPinnedMap(mapPath, nil)
			if err == nil {
				break
			}
		}
		if err == nil {
			defer m.Close()
			pinnedMaps[name] = m
		} else {
			logger.GetLogger().WithField("prog", load.Label).Debugf("pin file for map '%s' not found, map is not shared!\n", name)
		}
	}
	if err := spec.RewriteMaps(pinnedMaps); err != nil {
		return fmt.Errorf("rewrite maps failed: %w", err)
	}

	var opts ebpf.CollectionOptions
	if btfFile != nil {
		opts.Programs.TargetBTF = btfFile
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		// Retry again with logging to capture the verifier log. We don't log by default
		// as that makes the loading very slow.
		opts.Programs.LogLevel = 1
		opts.Programs.LogSize = verifierLogBufferSize
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			// Log the error directly using the logger so that the verifier log
			// gets properly pretty-printed.
			logger.GetLogger().Infof("Opening collection failed, dumping verifier log.")
			fmt.Println(slimVerifierError(err.Error()))

			return fmt.Errorf("opening collection '%s' failed", load.Name)
		}
	}
	defer coll.Close()

	err = installTailCalls(mapDirs[0], spec, coll)
	if err != nil {
		return fmt.Errorf("installing tail calls failed: %s", err)
	}

	prog, ok := coll.Programs[progSpec.Name]
	if !ok {
		return fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath)

	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Warnf("Pin file '%s' already exists, repinning", load.PinPath)
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %s", pinPath, err)
		}
	}

	// Clone the program so it can be passed on to attach function and unloader after
	// we close the collection.
	prog, err = prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone program '%s': %w", load.Label, err)
	}

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	load.unloader, err = withProgram(prog, progSpec)
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %w", pinPath, err)
		}
		return err
	}

	return nil
}
