// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Collection, *ebpf.CollectionSpec, *ebpf.Program, *ebpf.ProgramSpec) (unloader.Unloader, error)

type OpenFunc func(*ebpf.CollectionSpec) error

type LoadOpts struct {
	Attach AttachFunc
	Open   OpenFunc
}

func linkPinPath(bpfDir string, load *Program, extra ...string) string {
	pinPath := filepath.Join(bpfDir, load.PinPath, "link")
	if len(extra) != 0 {
		pinPath = pinPath + "_" + strings.Join(extra, "_")
	}
	return pinPath
}

func RawAttach(targetFD int) AttachFunc {
	return RawAttachWithFlags(targetFD, 0)
}

func RawAttachWithFlags(targetFD int, flags uint32) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("not supported on windows")
	}
}

func TracepointAttach(load *Program, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("not supported on windows")
	}
}

func RawTracepointAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("not supported on windows")

	}
}

func KprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		return fmt.Errorf("not supported on windows")
	}
}

func kprobeAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {
	return nil, fmt.Errorf("not supported on windows")
}

func windowsAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {

	link, err := link.AttachRawLink(link.RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsProcess,
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

func NoAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, _ *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}, nil
	}
}

func TracingAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("not supported on windows")
	}
}

func LSMOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		return fmt.Errorf("not supported on windows")
	}
}

func LSMAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("not supported on windows")
	}
}

func MultiKprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("not supported on windows")

	}
}

func LoadTracepointProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: TracepointAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadRawTracepointProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: RawTracepointAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadKprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadWindowsProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: WindowsAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func KprobeAttachMany(load *Program, syms []string, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		unloader := unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}

		for idx := range syms {
			un, err := kprobeAttach(load, prog, spec, syms[idx], bpfDir, fmt.Sprintf("%d_%s", idx, syms[idx]))
			if err != nil {
				return nil, err
			}

			unloader = append(unloader, un)
		}
		return unloader, nil
	}
}

func LoadKprobeProgramAttachMany(bpfDir string, load *Program, syms []string, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttachMany(load, syms, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadUprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: UprobeAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiKprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: MultiKprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadFmodRetProgram(bpfDir string, load *Program, progName string, verbose int) error {
	return fmt.Errorf("not supported on windows")
}

func LoadTracingProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: TracingAttach(),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
		Open:   LSMOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgramSimple(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiUprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: MultiUprobeAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

// MissingConstantsError is returned by [rewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return fmt.Sprintf("some constants are missing from .rodata: %s", strings.Join(m.Constants, ", "))
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

		//ToDo: Uncomment after map pinning issue is fixed
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
	// pin maps

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

// The loadProgram loads and attach bpf object @load. It is expected that user
// provides @loadOpts with mandatory attach function and optional open function.
//
// The load process is roughly as follows:
//
//   - load object              | ebpf.LoadCollectionSpec
//   - open callback            | loadOpts.open(spec)
//   - open refferenced maps    |
//   - creates collection       | ebpf.NewCollectionWithOptions(spec, opts)
//   - install tail calls       | loadOpts.ci
//   - load maps with values    |
//   - pin main program         |
//   - attach callback          | loadOpts.attach(coll, spec, prog, progSpec)
//   - print loaded progs/maps  | if KeepCollection == true
//
// The  @loadOpts.open callback can be used to customize ebpf.CollectionSpec
// before it's loaded into kernel (like disable/enable programs).
//
// The @loadOpts.attach callback is used to actually attach main object program
// to desired function/symbol/whatever..
//
// The @loadOpts.ci defines specific installation of tailcalls in object.

func loadProgram(
	bpfDir string,
	load *Program,
	opts *LoadOpts,
	verbose int,
) error {

	// Attach function is mandatory
	if opts.Attach == nil {
		return fmt.Errorf("attach function is not provided")
	}

	lc, err := doLoadProgram(bpfDir, load, opts, verbose)
	if err != nil {
		return err
	}
	if KeepCollection {
		load.LC = filterLoadedCollection(lc)
		printLoadedCollection(load.Name, load.LC)
	}
	return nil
}

func LoadProgram(
	bpfDir string,
	load *Program,
	attach AttachFunc,
	verbose int,
) error {
	return loadProgram(bpfDir, load, &LoadOpts{Attach: attach}, verbose)
}

func LoadProgramOpts(
	bpfDir string,
	load *Program,
	opts *LoadOpts,
	verbose int,
) error {
	return loadProgram(bpfDir, load, opts, verbose)
}
