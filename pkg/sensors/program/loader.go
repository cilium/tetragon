// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package program

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Collection, *ebpf.CollectionSpec, *ebpf.Program, *ebpf.ProgramSpec) (unloader.Unloader, error)

type OpenFunc func(*ebpf.CollectionSpec) error

type LoadOpts struct {
	Attach AttachFunc
	Open   OpenFunc
	Maps   []*Map
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

// MissingConstantsError is returned by [rewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return fmt.Sprintf("some constants are missing from .rodata: %s", strings.Join(m.Constants, ", "))
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
	maps []*Map,
	attach AttachFunc,
	verbose int,
) error {
	return loadProgram(bpfDir, load, &LoadOpts{Attach: attach, Maps: maps}, verbose)
}

func LoadProgramOpts(
	bpfDir string,
	load *Program,
	opts *LoadOpts,
	verbose int,
) error {
	return loadProgram(bpfDir, load, opts, verbose)
}
