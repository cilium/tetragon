// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/tetragon/pkg/bpf"
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

type uprobeAttachFunc func(*Program, *ebpf.Program, *ebpf.ProgramSpec, string, ...string) (unloader.Unloader, error)

func linkPin(lnk link.Link, bpfDir string, load *Program, extra ...string) error {
	// pinned link is not supported
	if !bpf.HasLinkPin() {
		return nil
	}

	pinPath := linkPinPath(bpfDir, load, extra...)

	err := lnk.Pin(pinPath)
	if err != nil {
		return fmt.Errorf("pinning link '%s' failed: %w", pinPath, err)
	}
	return nil
}

func RawAttachWithFlags(targetFD int, flags uint32) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  targetFD,
			Program: prog,
			Attach:  spec.AttachType,
			Flags:   flags,
		})
		if err != nil {
			prog.Close()
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
			&unloader.RawDetachUnloader{
				TargetFD:   targetFD,
				Name:       spec.Name,
				Prog:       prog,
				AttachType: spec.AttachType,
			},
		}, nil
	}
}

func TracepointAttach(load *Program, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		parts := strings.Split(load.Attach, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("tracepoint attach argument must be in the form category/tracepoint, got: %s", load.Attach)
		}
		tpLink, err := link.Tracepoint(parts[0], parts[1], prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		err = linkPin(tpLink, bpfDir, load)
		if err != nil {
			tpLink.Close()
			return nil, err
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       tpLink,
			RelinkFn: func() (link.Link, error) {
				return link.Tracepoint(parts[0], parts[1], prog, nil)
			},
		}, nil
	}
}

func RawTracepointAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		var lnk link.Link
		var err error

		parts := strings.Split(load.Attach, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("raw_tracepoint attach argument must be in the form category/tracepoint, got: %s", load.Attach)
		}
		lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    parts[1],
			Program: prog,
		})
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
			unloader.LinkUnloader{
				Link: lnk,
			},
		}, nil
	}
}

func disableProg(coll *ebpf.CollectionSpec, name string) {
	if spec, ok := coll.Programs[name]; ok {
		spec.Type = ebpf.UnspecifiedProgram
	}
}

func KprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		// The generic_kprobe_override program is part of bpf_generic_kprobe.o object,
		// so let's disable it if the override is not configured. Otherwise it gets
		// loaded and bpftool will show it.
		if !load.Override {
			disableProg(coll, "generic_kprobe_override")
			disableProg(coll, "generic_fmodret_override")
		} else {
			if load.OverrideFmodRet {
				spec, ok := coll.Programs["generic_fmodret_override"]
				if !ok {
					return errors.New("failed to find generic_fmodret_override")
				}
				spec.AttachTo = load.Attach
				disableProg(coll, "generic_kprobe_override")
			} else {
				disableProg(coll, "generic_fmodret_override")
			}
		}
		return nil
	}
}

func kprobeAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {
	var linkFn func() (link.Link, error)

	if load.RetProbe {
		linkFn = func() (link.Link, error) { return link.Kretprobe(symbol, prog, nil) }
	} else {
		linkFn = func() (link.Link, error) { return link.Kprobe(symbol, prog, nil) }
	}

	lnk, err := linkFn()
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}
	err = linkPin(lnk, bpfDir, load, extra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}
	load.Link = lnk
	return &unloader.RelinkUnloader{
		UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
		IsLinked:   true,
		Link:       lnk,
		RelinkFn:   linkFn,
	}, nil
}

func kprobeAttachOverride(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec) error {

	spec, ok := collSpec.Programs["generic_kprobe_override"]
	if !ok {
		return errors.New("spec for generic_kprobe_override program not found")
	}

	prog, ok := coll.Programs["generic_kprobe_override"]
	if !ok {
		return errors.New("program generic_kprobe_override not found")
	}

	prog, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone generic_kprobe_override program: %w", err)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath, "prog_override")

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	load.unloaderOverride, err = kprobeAttach(load, prog, spec, load.Attach, bpfDir, "override")
	if err != nil {
		logger.GetLogger().Warn("Failed to attach override program", logfields.Error, err)
	}

	return nil
}

func fmodretAttachOverride(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec) error {

	spec, ok := collSpec.Programs["generic_fmodret_override"]
	if !ok {
		return errors.New("spec for generic_fmodret_override program not found")
	}

	prog, ok := coll.Programs["generic_fmodret_override"]
	if !ok {
		return errors.New("program generic_fmodret_override not found")
	}

	prog, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone generic_fmodret_override program: %w", err)
	}

	pinPath := filepath.Join(bpfDir, filepath.Join(load.PinPath, "prog_override"))

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	linkFn := func() (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
	}

	lnk, err := linkFn()
	if err != nil {
		return fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}

	err = linkPin(lnk, bpfDir, load, "override")
	if err != nil {
		lnk.Close()
		return err
	}

	load.unloaderOverride = &unloader.RelinkUnloader{
		UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
		IsLinked:   true,
		Link:       lnk,
		RelinkFn:   linkFn,
	}

	return nil
}

func KprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		if load.Override {
			if load.OverrideFmodRet {
				if err := fmodretAttachOverride(load, bpfDir, coll, collSpec); err != nil {
					return nil, err
				}
			} else {
				if err := kprobeAttachOverride(load, bpfDir, coll, collSpec); err != nil {
					return nil, err
				}
			}
		}

		return kprobeAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func UprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		if !load.SleepableOffload {
			disableProg(coll, "generic_sleepable_offload")
		}
		return nil
	}
}

func UprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return uprobeAttach(load, bpfDir, coll, collSpec, prog, spec, uprobeAttachSingle)
	}
}

func uprobeAttachSingle(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	data, ok := load.AttachData.(*UprobeAttachData)
	if !ok {
		return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
	}

	linkFn := func() (link.Link, error) {
		exec, err := link.OpenExecutable(data.Path)
		if err != nil {
			return nil, err
		}
		opts := &link.UprobeOptions{
			Address:      data.Address,
			RefCtrOffset: data.RefCtrOffset,
			Offset:       data.Offset,
		}
		if load.RetProbe {
			return exec.Uretprobe(data.Symbol, prog, opts)
		}
		return exec.Uprobe(data.Symbol, prog, opts)
	}

	lnk, err := linkFn()
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}

	err = linkPin(lnk, bpfDir, load, extra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}

	return &unloader.RelinkUnloader{
		UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
		IsLinked:   true,
		Link:       lnk,
		RelinkFn:   linkFn,
	}, nil
}

func MultiUprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return uprobeAttach(load, bpfDir, coll, collSpec, prog, spec, uprobeAttachMulti)
	}
}

func uprobeAttachMulti(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	data, ok := load.AttachData.(*MultiUprobeAttachData)
	if !ok {
		return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
	}

	linkFn := func() ([]link.Link, error) {
		var links []link.Link
		var lnk link.Link

		for path, attach := range data.Attach {
			exec, err := link.OpenExecutable(path)
			if err != nil {
				return nil, err
			}
			opts := &link.UprobeMultiOptions{
				Addresses:     attach.Addresses,
				Offsets:       attach.Offsets,
				RefCtrOffsets: attach.RefCtrOffsets,
				Cookies:       attach.Cookies,
			}
			if load.RetProbe {
				lnk, err = exec.UretprobeMulti(attach.Symbols, prog, opts)
			} else {
				lnk, err = exec.UprobeMulti(attach.Symbols, prog, opts)
			}
			if err != nil {
				return nil, err
			}
			err = linkPin(lnk, bpfDir, load, extra...)
			if err != nil {
				lnk.Close()
				return nil, err
			}
			links = append(links, lnk)
		}
		return links, nil
	}

	links, err := linkFn()
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}

	return &unloader.MultiRelinkUnloader{
		UnloadProg: unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}.Unload,
		IsLinked: true,
		Links:    links,
		RelinkFn: linkFn,
	}, nil
}

func uprobeAttachExtra(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	progName, pin string, attach uprobeAttachFunc) (unloader.Unloader, error) {

	spec, ok := collSpec.Programs[progName]
	if !ok {
		return nil, fmt.Errorf("spec for %s program not found", progName)
	}

	prog, ok := coll.Programs[progName]
	if !ok {
		return nil, fmt.Errorf("program %s not found", progName)
	}

	prog, err := prog.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone %s program: %w", progName, err)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath, fmt.Sprint("prog_", pin))

	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	return attach(load, prog, spec, bpfDir, pin)
}

func uprobeAttach(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	prog *ebpf.Program, spec *ebpf.ProgramSpec, attach uprobeAttachFunc) (unloader.Unloader, error) {

	var (
		err              error
		main             unloader.Unloader
		sleepableOffload unloader.Unloader
	)

	if load.SleepableOffload {
		if sleepableOffload, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_offload", "sleepable_offload", attach); err != nil {
			return nil, err
		}
	}

	if main, err = attach(load, prog, spec, bpfDir); err != nil {
		if sleepableOffload != nil {
			sleepableOffload.Unload(true)
		}
		return nil, err
	}

	return unloader.ChainUnloader{
		main,
		sleepableOffload,
	}, nil
}

func TracingAttach(load *Program, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		linkFn := func() (link.Link, error) {
			return link.AttachTracing(link.TracingOptions{
				Program: prog,
			})
		}
		lnk, err := linkFn()
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		err = linkPin(lnk, bpfDir, load)
		if err != nil {
			lnk.Close()
			return nil, err
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       lnk,
			RelinkFn:   linkFn,
		}, nil
	}
}

func LSMOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		for _, prog := range coll.Programs {
			if prog.AttachType == ebpf.AttachLSMMac {
				prog.AttachTo = load.Attach
			} else {
				return errors.New("only AttachLSMMac is supported for generic_lsm programs")
			}
		}
		return nil
	}
}

func LSMAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		linkFn := func() (link.Link, error) {
			return link.AttachLSM(link.LSMOptions{
				Program: prog,
			})
		}
		lnk, err := linkFn()
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       lnk,
			RelinkFn:   linkFn,
		}, nil
	}
}

func multiKprobeAttach(load *Program, prog *ebpf.Program,
	spec *ebpf.ProgramSpec, opts link.KprobeMultiOptions,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	var lnk link.Link
	var err error

	if load.RetProbe {
		lnk, err = link.KretprobeMulti(prog, opts)
	} else {
		lnk, err = link.KprobeMulti(prog, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}
	err = linkPin(lnk, bpfDir, load, extra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}
	load.Link = lnk
	return unloader.ChainUnloader{
		unloader.ProgUnloader{
			Prog: prog,
		},
		unloader.LinkUnloader{
			Link: lnk,
		},
	}, nil
}

func MultiKprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		data, ok := load.AttachData.(*MultiKprobeAttachData)
		if !ok {
			return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
		}

		if load.Override {
			progOverrideSpec, ok := collSpec.Programs["generic_kprobe_override"]
			if ok {
				progOverrideSpec.Type = ebpf.UnspecifiedProgram
			}

			progOverride, ok := coll.Programs["generic_kprobe_override"]
			if !ok {
				return nil, fmt.Errorf("program for section '%s' not found", load.Label)
			}

			progOverride, err := progOverride.Clone()
			if err != nil {
				return nil, fmt.Errorf("failed to clone program '%s': %w", load.Label, err)
			}

			pinPath := filepath.Join(bpfDir, filepath.Join(load.PinPath, "prog_override"))

			if err := progOverride.Pin(pinPath); err != nil {
				return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
			}

			opts := link.KprobeMultiOptions{
				Symbols: data.Overrides,
			}

			load.unloaderOverride, err = multiKprobeAttach(load, progOverride, progOverrideSpec, opts, bpfDir, "override")
			if err != nil {
				logger.GetLogger().Warn("Failed to attach override program", logfields.Error, err)
			}
		}

		opts := link.KprobeMultiOptions{
			Symbols: data.Symbols,
			Cookies: data.Cookies,
		}

		return multiKprobeAttach(load, prog, spec, opts, bpfDir)
	}
}

func LoadTracepointProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: TracepointAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadRawTracepointProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: RawTracepointAttach(load),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadKprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
		Maps:   maps,
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

func LoadKprobeProgramAttachMany(bpfDir string, load *Program, syms []string, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttachMany(load, syms, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Open:   UprobeOpen(load),
		Attach: UprobeAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiKprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: MultiKprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadFmodRetProgram(bpfDir string, load *Program, maps []*Map, progName string, verbose int) error {
	opts := &LoadOpts{
		Attach: func(
			_ *ebpf.Collection,
			_ *ebpf.CollectionSpec,
			prog *ebpf.Program,
			spec *ebpf.ProgramSpec,
		) (unloader.Unloader, error) {
			linkFn := func() (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program: prog,
				})
			}
			lnk, err := linkFn()
			if err != nil {
				return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
			}
			return &unloader.RelinkUnloader{
				UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
				IsLinked:   true,
				Link:       lnk,
				RelinkFn:   linkFn,
			}, nil
		},
		Open: func(coll *ebpf.CollectionSpec) error {
			progSpec, ok := coll.Programs[progName]
			if !ok {
				return fmt.Errorf("progName %s not in collecition spec programs: %+v", progName, coll.Programs)
			}
			progSpec.AttachTo = load.Attach
			return nil
		},
		Maps: maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadTracingProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: TracingAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
		Open:   LSMOpen(load),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgramSimple(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Open:   UprobeOpen(load),
		Attach: MultiUprobeAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func SeccompAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, _ *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return &unloader.ProgUnloader{
			Prog: prog,
		}, nil
	}
}

func LoadSeccompProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Attach: SeccompAttach(),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
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

func installTailCalls(bpfDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection, load *Program) error {
	// FIXME(JM): This should be replaced by using the cilium/ebpf prog array initialization.

	secToProgName := make(map[string]string)
	for name, prog := range spec.Programs {
		secToProgName[prog.SectionName] = name
	}

	install := func(pinPath string, secPrefix string) error {
		tailCallsMap, err := ebpf.LoadPinnedMap(filepath.Join(bpfDir, pinPath), nil)
		if err != nil {
			return nil
		}
		defer tailCallsMap.Close()

		for i := range 13 {
			secName := fmt.Sprintf("%s/%d", secPrefix, i)
			if progName, ok := secToProgName[secName]; ok {
				if prog, ok := coll.Programs[progName]; ok {
					err := tailCallsMap.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny)
					if err != nil {
						return fmt.Errorf("update of tail-call map '%s' failed: %w", pinPath, err)
					}
				}
			}
		}
		return nil
	}

	if load.TcMap != nil {
		if err := install(load.TcMap.PinPath, load.TcPrefix); err != nil {
			return err
		}
	}

	return nil
}

func rewriteConstants(spec *ebpf.CollectionSpec, consts map[string]any) error {
	var missing []string

	for n, c := range consts {
		v, ok := spec.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}

func doLoadProgram(
	bpfDir string,
	load *Program,
	loadOpts *LoadOpts,
	verbose int,
) (*LoadedCollection, error) {
	var btfSpec *btf.Spec
	if btfFilePath := cachedbtf.GetCachedBTFFile(); btfFilePath != "/sys/kernel/btf/vmlinux" {
		// Non-standard path to BTF, open it and provide it as 'KernelTypes'.
		var err error
		btfSpec, err = btf.LoadSpec(btfFilePath)
		if err != nil {
			return nil, fmt.Errorf("opening BTF file '%s' failed: %w", btfFilePath, err)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(load.Name)
	if err != nil {
		return nil, fmt.Errorf("loading collection spec failed: %w", err)
	}

	if load.RewriteConstants != nil {
		if err := rewriteConstants(spec, load.RewriteConstants); err != nil {
			return nil, fmt.Errorf("rewritting constants in spec failed: %w", err)
		}
	}

	if loadOpts.Open != nil {
		if err := loadOpts.Open(spec); err != nil {
			return nil, fmt.Errorf("open spec function failed: %w", err)
		}
	}

	// We have following maps available for loading:
	// - maps attached/pinned to program directly in load.PinMap[name]
	// - maps passed to loader (all sensor maps)
	//
	// We need to resolve maps (find program.Map object) to be able to
	// complete following operations:
	//
	//  (1) before loading:
	//   - setup maps max entries values
	//   - resolve all program's referenced maps
	//
	//  (2) after loading:
	//   - load values to maps via load.MapLoad interface
	//
	// The resolveMap function is used for (1) and takes map name and
	// searches for map object in following order:
	//
	//   1) load.PinMap[name]
	//   2) loadOpts.Maps user maps
	//
	// For (2) we search only maps that the program owns, which are
	// placed in load.PinMap.

	userMaps := map[string]*Map{}
	for _, pm := range loadOpts.Maps {
		if !pm.IsOwner() {
			userMaps[pm.Name] = pm
		}
	}

	resolveMap := func(name string) (*Map, bool) {
		m, ok := load.PinMap[name]
		if ok {
			return m, true
		}
		m, ok = userMaps[name]
		return m, ok
	}

	for _, ms := range spec.Maps {
		m, ok := resolveMap(ms.Name)
		if !ok {
			continue
		}

		if maximum, ok := m.GetMaxEntries(); ok {
			ms.MaxEntries = maximum
		}

		if innerMax, ok := m.GetMaxInnerEntries(); ok {
			if ms.InnerMap == nil {
				return nil, fmt.Errorf("no inner map for %s", ms.Name)
			}
			ms.InnerMap.MaxEntries = innerMax
		}
	}

	// Find all the maps referenced by the program, so we'll rewrite only
	// the ones used.
	var progSpec *ebpf.ProgramSpec

	refMaps := make(map[string]bool)
	for _, prog := range spec.Programs {
		if prog.SectionName == load.Label {
			progSpec = prog
		}
		for _, inst := range prog.Instructions {
			if inst.Reference() != "" {
				refMaps[inst.Reference()] = true
			}
		}
	}

	if progSpec == nil {
		return nil, fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinnedMaps := make(map[string]*ebpf.Map)
	for name := range refMaps {
		var m *ebpf.Map
		var err error
		var mapPath string

		if pm, ok := resolveMap(name); ok {
			mapPath = filepath.Join(bpfDir, pm.PinPath)
		} else {
			mapPath = filepath.Join(bpfDir, name)
		}
		m, err = ebpf.LoadPinnedMap(mapPath, nil)
		if err == nil {
			defer m.Close()
			pinnedMaps[name] = m
		} else {
			logger.GetLogger().Debug(fmt.Sprintf("pin file for map '%s' not found, map is not shared!\n", name), "prog", load.Label)
		}
	}

	var opts ebpf.CollectionOptions
	if btfSpec != nil {
		// we have a BTF in a non-normal location let's use that in the first try
		opts.Programs.KernelTypes = btfSpec
	} else if load.KernelTypes != nil {
		// here we have the nornal BTF file (i.e. /sys/kernel/btf/vmlinux) and we can
		// check if the user provided any custom BTF (i.e. containing kmod data) and use
		// that instead
		opts.Programs.KernelTypes = load.KernelTypes
	}

	opts.MapReplacements = pinnedMaps

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil && btfSpec != nil && load.KernelTypes != nil {
		// here we have tried using btfSpec and failed now let's
		// try to use the user-provided load.KernelTypes
		opts.Programs.KernelTypes = load.KernelTypes
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
	}
	if err != nil {
		// Log the error directly using the logger so that the verifier log
		// gets properly pretty-printed.
		if verbose != 0 {
			logger.GetLogger().Info("Opening collection failed, dumping verifier log.")
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				// Print a truncated version if we have verbose=1, otherwise dump the
				// full log.
				if verbose < 2 {
					fmt.Println(slimVerifierError(fmt.Sprintf("%+v", ve)))
				} else {
					fmt.Printf("%+v\n", ve)
				}
			}
		}

		return nil, fmt.Errorf("opening collection '%s' failed: %w", load.Name, err)
	}
	defer coll.Close()

	// This is for accounting of the BPF map memlock usage. At first I thought I
	// could just read the coll.Maps but those contain (a lot of) unused maps in
	// the ELF file (e.g. tg_cgrps_tracking_map) that are loaded initially but
	// not used or referenced anywhere so GCed as soon as we close the reference
	// on the collection.
	//
	// The way we found is to browse which maps are used from the returned
	// programs in the collection. Since for those programs we keep a reference
	// anyway, they can't be garbage collected.
	collMaps := map[ebpf.MapID]*ebpf.Map{}
	// we need a mapping by ID
	for _, m := range coll.Maps {
		info, err := m.Info()
		if err != nil {
			logger.GetLogger().Warn("failed to retrieve BPF map info", "map", m.String(), logfields.Error, err)
			break
		}
		id, available := info.ID()
		if !available {
			logger.GetLogger().Warn("failed to retrieve BPF map ID, you might be running <4.13", "map", m.String())
			break
		}
		collMaps[id] = m
	}
	load.LoadedMapsInfo = map[int]bpf.ExtendedMapInfo{}
	for _, p := range coll.Programs {
		i, err := p.Info()
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

	err = installTailCalls(bpfDir, spec, coll, load)
	if err != nil {
		return nil, fmt.Errorf("installing tail calls failed: %w", err)
	}

	for _, mapLoad := range load.MapLoad {
		pinPath := ""
		// We allow to load only maps that we own.
		if pm, ok := load.PinMap[mapLoad.Name]; ok {
			pinPath = pm.PinPath
		}
		if m, ok := coll.Maps[mapLoad.Name]; ok {
			if err := mapLoad.Load(m, pinPath); err != nil {
				return nil, fmt.Errorf("map load for %s failed: %w", mapLoad.Name, err)
			}
		} else {
			return nil, fmt.Errorf("populating map failed as map '%s' was not found from collection", mapLoad.Name)
		}
	}

	prog, ok := coll.Programs[progSpec.Name]
	if !ok {
		return nil, fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath, "prog")

	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Debug(fmt.Sprintf("Pin file '%s' already exists, repinning", load.PinPath))
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Unpinning '%s' failed", pinPath), logfields.Error, err)
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

	load.unloader, err = loadOpts.Attach(coll, spec, prog, progSpec)
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Unpinning '%s' failed", pinPath), logfields.Error, err)
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
