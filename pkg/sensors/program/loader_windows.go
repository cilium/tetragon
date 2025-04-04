// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
	"golang.org/x/sys/windows"
)

var (
	notSupportedWinErr     = errors.New("not supported on windows")
	programTypeProcessGUID = makeGUID(0x22ea7b37, 0x1043, 0x4d0d, [8]byte{0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e})
	attachTypeProcessGUID  = makeGUID(0x66e20687, 0x9805, 0x4458, [8]byte{0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85})
)

func makeGUID(data1 uint32, data2 uint16, data3 uint16, data4 [8]byte) windows.GUID {
	return windows.GUID{Data1: data1, Data2: data2, Data3: data3, Data4: data4}
}

func winAttachStub(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
	prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

	return nil, notSupportedWinErr
}

func RawAttachWithFlags(targetFD int, flags uint32) AttachFunc {
	return winAttachStub
}

func TracepointAttach(load *Program, bpfDir string) AttachFunc {
	return winAttachStub
}

func RawTracepointAttach(load *Program) AttachFunc {
	return winAttachStub
}

func KprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		return notSupportedWinErr
	}
}

func kprobeAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {
	return nil, notSupportedWinErr
}

func windowsAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {

	attachType, err := ebpf.WindowsAttachTypeForGUID(attachTypeProcessGUID.String())
	if err != nil {
		return nil, err
	}

	link, err := link.AttachRawLink(link.RawLinkOptions{
		Program: prog,
		Attach:  attachType,
	})
	if err != nil {
		return nil, err
	}
	return unloader.ChainUnloader{
		unloader.ProgUnloader{
			Prog: prog,
		},
		unloader.LinkUnloader{
			Link: link,
		},
	}, nil

}

func WindowsAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return windowsAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func KprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return kprobeAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func UprobeAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("not supported on windows")

	}
}

func MultiUprobeAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("not supported on windows")

	}
}

func TracingAttach(load *Program, bpfDir string) AttachFunc {
	return winAttachStub
}

func LSMOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		return fmt.Errorf("not supported on windows")
	}
}

func LSMAttach() AttachFunc {
	return winAttachStub
}

func MultiKprobeAttach(load *Program, bpfDir string) AttachFunc {
	return winAttachStub
}

func LoadWindowsProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: WindowsAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadTracepointProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadRawTracepointProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadKprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func KprobeAttachMany(load *Program, syms []string, bpfDir string) AttachFunc {
	return winAttachStub
}

func LoadKprobeProgramAttachMany(bpfDir string, load *Program, syms []string, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadMultiKprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadFmodRetProgram(bpfDir string, load *Program, maps []*Map, progName string, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadTracingProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadLSMProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadLSMProgramSimple(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func LoadMultiUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	return constants.ErrWindowsNotSupported
}

func doLoadProgram(
	bpfDir string,
	load *Program,
	loadOpts *LoadOpts,
	verbose int,
) (*LoadedCollection, error) {

	coll, err := ebpf.LoadCollection(load.Name)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("Error ", err.Error()).Warn(" Failed to load Native Windows Collection ")
		return nil, err
	}
	bpf.SetExecCollection(coll)

	collMaps := map[ebpf.MapID]*ebpf.Map{}
	// we need a mapping by ID
	for _, m := range coll.Maps {

		info, err := m.Info()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("map", m.String()).Warn("failed to retrieve BPF map info")
			continue
		}
		id, available := info.ID()
		if !available {
			logger.GetLogger().WithField("map", m.String()).Warn("failed to retrieve BPF map ID, you might be running <4.13")
			continue
		}
		collMaps[id] = m

		// In Windows, this is where we pin maps.
		// ToDo: Pinned maps do not get unpinned when tetragon stops,
		// This is to be uncommented once that issue is fixed.
		// We do not need pinned maps for events
		// if _, exist := load.PinMap[info.Name]; exist {
		// 	pinPath := load.Attach + "::" + info.Name
		// 	err = m.Pin(pinPath)
		// 	if err != nil {
		// 		logger.GetLogger().WithField("map", m.String()).Warn("failed to pin map")
		// 	} else {
		// 		logger.GetLogger().WithField("map tp path  ", pinPath).Info("Successfully pinned")
		// 	}
		// }
	}

	load.LoadedMapsInfo = map[int]bpf.ExtendedMapInfo{}

	var prog *ebpf.Program
	for _, p := range coll.Programs {

		i, err := p.Info()
		if i.Name == load.Label {
			prog = p
		}
		if err != nil {
			logger.GetLogger().WithError(err).WithField("program", p.String()).Warn("failed to retrieve BPF program info, you might be running <4.10")
			break
		}
		ids, available := i.MapIDs()
		if !available {
			logger.GetLogger().WithField("program", p.String()).Warn("failed to retrieve BPF program map IDs, you might be running <4.15")
			break
		}
		for _, id := range ids {
			if _, exist := load.LoadedMapsInfo[int(id)]; exist {
				continue
			}
			xInfo, err := bpf.ExtendedInfoFromMap(collMaps[id])
			if err != nil {
				logger.GetLogger().WithError(err).WithField("mapID", id).Warn("failed to retrieve extended map info")
				break
			}
			load.LoadedMapsInfo[int(id)] = xInfo
		}
	}

	for _, mapLoad := range load.MapLoad {
		pinPath := ""
		if pm, ok := load.PinMap[mapLoad.Name]; ok {
			pinPath = pm.PinPath
		}
		if m, ok := coll.Maps[mapLoad.Name]; ok {
			if err := mapLoad.Load(m, pinPath, mapLoad.Index); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("populating map failed as map '%s' was not found from collection", mapLoad.Name)
		}
	}
	if prog == nil {
		return nil, fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := load.PinPath
	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Debugf("Pin file '%s' already exists, repinning", load.PinPath)
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %s", pinPath, err)
		}
	}

	// Clone the program so it can be passed on to attach function and unloader after
	// we close the collection.
	prog, err = prog.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone program '%s': %w", load.Label, err)
	}

	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	load.unloader, err = loadOpts.Attach(coll, nil, prog, nil)
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %w", pinPath, err)
		}
		return nil, err
	}

	load.Prog = prog

	// in KernelTypes, we use a non-standard BTF which is possibly annotated with symbols
	// from kernel modules. At this point we don't need that anymore, so we can release
	// the memory from it.
	load.KernelTypes = nil

	// Copy the loaded collection before it's destroyed
	if KeepCollection {
		return copyLoadedCollection(coll)
	}
	return nil, nil
}
