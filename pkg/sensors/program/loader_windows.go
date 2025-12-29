// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

var (
	attachTypeBindGUID                  = makeGUID(0xb9707e04, 0x8127, 0x4c72, [8]byte{0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96})
	attachTypeProcessGUID               = makeGUID(0x66e20687, 0x9805, 0x4458, [8]byte{0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85})
	attachTypeCgroupSockOpsGUID         = makeGUID(0x837d02cd, 0x3251, 0x4632, [8]byte{0x8d, 0x94, 0x60, 0xd3, 0xb4, 0x57, 0x69, 0xf2})
	attachTypeCgroupInet4ConnectGUID    = makeGUID(0xa82e37b1, 0xaee7, 0x11ec, [8]byte{0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee})
	attachTypeCgroupInet6ConnectGUID    = makeGUID(0xa82e37b2, 0xaee7, 0x11ec, [8]byte{0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee})
	attachTypeCgroupInet4RecvAcceptGUID = makeGUID(0xa82e37b3, 0xaee7, 0x11ec, [8]byte{0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee})
	attachTypeCgroupInet6RecvAcceptGUID = makeGUID(0xa82e37b4, 0xaee7, 0x11ec, [8]byte{0x9a, 0x30, 0x18, 0x60, 0x24, 0x89, 0xbe, 0xee})

	attachTypeMap = map[string]string{
		"process":             attachTypeProcessGUID.String(),
		"cgroup/connect4":     attachTypeCgroupInet4ConnectGUID.String(),
		"cgroup/connect6":     attachTypeCgroupInet6ConnectGUID.String(),
		"cgroup/recv_accept4": attachTypeCgroupInet4RecvAcceptGUID.String(),
		"cgroup/recv_accept6": attachTypeCgroupInet6RecvAcceptGUID.String(),
		"bind":                attachTypeBindGUID.String(),
		"sockops":             attachTypeCgroupSockOpsGUID.String(),
	}
)

func makeGUID(data1 uint32, data2 uint16, data3 uint16, data4 [8]byte) windows.GUID {
	return windows.GUID{Data1: data1, Data2: data2, Data3: data3, Data4: data4}
}

func winAttachStub(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
	_ *ebpf.Program, _ *ebpf.ProgramSpec) (unloader.Unloader, error) {

	return nil, constants.ErrWindowsNotSupported
}

func RawAttachWithFlags(_ int, _ uint32) AttachFunc {
	return winAttachStub
}

func getAttachTypeForAttachTarget(attachTarget string) (ebpf.AttachType, error) {
	attachTypeGuid, ok := attachTypeMap[attachTarget]
	if !ok {
		return ebpf.AttachNone, nil
	}
	return ebpf.WindowsAttachTypeForGUID(attachTypeGuid)
}

func windowsAttach(_ *Program, prog *ebpf.Program, _ *ebpf.ProgramSpec,
	attach string, _ string, _ ...string) (unloader.Unloader, error) {

	attachType, err := getAttachTypeForAttachTarget(attach)
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
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return windowsAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func LoadWindowsProgram(bpfDir string, load *Program, _ []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: WindowsAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadTracepointProgram(_ string, _ *Program, _ []*Map, _ int) error {
	return constants.ErrWindowsNotSupported
}

func LoadKprobeProgramAttachMany(_ string, _ *Program, _ []string, _ []*Map, _ int) error {
	return constants.ErrWindowsNotSupported
}

func LoadMultiKprobeProgram(_ string, _ *Program, _ []*Map, _ int) error {
	return constants.ErrWindowsNotSupported
}

func LoadFmodRetProgram(_ string, _ *Program, _ []*Map, _ string, _ int) error {
	return constants.ErrWindowsNotSupported
}

func doLoadProgram(
	_ string,
	load *Program,
	loadOpts *LoadOpts,
	_ int,
	keepCollection bool,
) (*LoadedCollection, error) {

	coll, err := bpf.GetCollectionByPath(load.Name)
	if err != nil {
		coll, err = ebpf.LoadCollection(load.Name)
		if err != nil {
			logger.GetLogger().Warn(" Failed to load Native Windows Collection", logfields.Error, err)
			return nil, err
		}
		bpf.SetCollection(load.Label, load.Name, coll)
	}

	collMaps := map[ebpf.MapID]*ebpf.Map{}
	// we need a mapping by ID
	for _, m := range coll.Maps {

		info, err := m.Info()
		if err != nil {
			logger.GetLogger().Warn("failed to retrieve BPF map info", "map", m.String(), logfields.Error, err)
			continue
		}
		id, available := info.ID()
		if !available {
			logger.GetLogger().Warn("failed to retrieve BPF map ID, you might be running <4.13", "map", m.String())
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
			logger.GetLogger().Warn("failed to retrieve BPF program info, you might be running <4.10", "program", p.String(), logfields.Error, err)
			break
		}
		ids, available := i.MapIDs()
		if !available {
			logger.GetLogger().Warn("failed to retrieve BPF program map IDs, you might be running <4.15", "program", p.String())
			break
		}
		for _, id := range ids {
			if _, exist := load.LoadedMapsInfo[int(id)]; exist {
				continue
			}
			xInfo, err := bpf.ExtendedInfoFromMap(collMaps[id])
			if err != nil {
				logger.GetLogger().Warn("failed to retrieve extended map info", "mapID", id, logfields.Error, err)
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
			if err := mapLoad.Load(m, pinPath); err != nil {
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
		logger.GetLogger().Debug(fmt.Sprintf("Pin file '%s' already exists, repinning", load.PinPath))
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warn("Unpinning failed", "pinPath", pinPath, logfields.Error, err)
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
			logger.GetLogger().Warn("Unpinning failed", "pinPath", pinPath, logfields.Error, err)
		}
		return nil, err
	}

	load.Prog = prog

	// in KernelTypes, we use a non-standard BTF which is possibly annotated with symbols
	// from kernel modules. At this point we don't need that anymore, so we can release
	// the memory from it.
	load.KernelTypes = nil

	// Copy the loaded collection before it's destroyed
	if keepCollection {
		return copyLoadedCollection(coll)
	}
	return nil, nil
}
