// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

type uprobeAttachFunc func(*Program, *ebpf.Program, *ebpf.ProgramSpec, string, ...string) (unloader.Unloader, error)

func procSelfFDPath(f *os.File) string {
	return filepath.Join(option.Config.ProcFS, "self", "fd", strconv.FormatUint(uint64(f.Fd()), 10))
}

func UprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		if !load.SleepableOffload {
			disableProg(coll, "generic_sleepable_offload")
		}
		if !load.SleepablePreload {
			disableProg(coll, "generic_sleepable_preload")
			disableProg(coll, "generic_sleepable_preload_cleanup")
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
		// The kernel tracks uprobe targets by inode. When we open a file,
		// its file descriptor points to an inode.
		// The loader API requires that a path is provided. It will not accept
		// a file descriptor directly. But we can use the procfs self/fd/<N> symlink
		// to reference the file descriptor, which is a stable reference to the
		// inode even if the path's inode changes.
		// This trick ensures that the uprobe attachment is not affected by TOCTOU issues
		// with the target file.
		f, err := os.Open(data.Path)
		if err != nil {
			return nil, fmt.Errorf("open executable %s: %w", data.Path, err)
		}
		defer f.Close()
		fdPath := procSelfFDPath(f)
		exec, err := link.OpenExecutable(fdPath)
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

	err = LinkPin(lnk, bpfDir, load, extra...)
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

func attachMultiUpobeLink(load *Program, prog *ebpf.Program, path string, attach *MultiUprobeAttachSymbolsCookies, bpfDir string, idx int, extra ...string) (link.Link, error) {
	// The kernel tracks uprobe targets by inode. When we open a file,
	// its file descriptor points to an inode.
	// The loader API requires that a path is provided. It will not accept
	// a file descriptor directly. But we can use the procfs self/fd/<N> symlink
	// to reference the file descriptor, which is a stable reference to the
	// inode even if the path's inode changes.
	// This trick ensures that the uprobe attachment is not affected by TOCTOU issues
	// with the target file.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", path, err)
	}
	defer f.Close()
	fdPath := procSelfFDPath(f)
	exec, err := link.OpenExecutable(fdPath)
	if err != nil {
		return nil, err
	}
	opts := &link.UprobeMultiOptions{
		Addresses:     attach.Addresses,
		Offsets:       attach.Offsets,
		RefCtrOffsets: attach.RefCtrOffsets,
		Cookies:       attach.Cookies,
	}
	var lnk link.Link
	if load.RetProbe {
		lnk, err = exec.UretprobeMulti(attach.Symbols, prog, opts)
	} else {
		lnk, err = exec.UprobeMulti(attach.Symbols, prog, opts)
	}
	if err != nil {
		return nil, err
	}
	pinExtra := append(extra, strconv.Itoa(idx))
	err = LinkPin(lnk, bpfDir, load, pinExtra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}
	return lnk, nil
}

func uprobeAttachMulti(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	data, ok := load.AttachData.(*MultiUprobeAttachData)
	if !ok {
		return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
	}

	linkFn := func() ([]link.Link, error) {
		var links []link.Link

		idx := 0
		for path, attach := range data.Attach {
			lnk, err := attachMultiUpobeLink(load, prog, path, attach, bpfDir, idx, extra...)
			if err != nil {
				return nil, err
			}
			links = append(links, lnk)
			idx++
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

	un, err := attach(load, prog, spec, bpfDir, pin)
	if err != nil {
		prog.Unpin()
	}
	return un, err
}

func uprobeAttach(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	prog *ebpf.Program, spec *ebpf.ProgramSpec, attach uprobeAttachFunc) (un unloader.Unloader, err error) {

	var (
		main             unloader.Unloader
		sleepableOffload unloader.Unloader
		sleepablePreload unloader.Unloader
		sleepableCleanup unloader.Unloader
	)

	defer func() {
		un = unloader.ChainUnloader{
			main,
			sleepableOffload,
			sleepablePreload,
			sleepableCleanup,
		}
		if err != nil {
			un.Unload(true)
			un = nil
		}
	}()

	if load.SleepableOffload {
		if sleepableOffload, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_offload", "sleepable_offload", attach); err != nil {
			return nil, err
		}
	}

	if load.SleepablePreload {
		if sleepableCleanup, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_preload_cleanup", "sleepable_preload_cleanup", attach); err != nil {
			return nil, err
		}
	}

	if main, err = attach(load, prog, spec, bpfDir); err != nil {
		return nil, err
	}

	if load.SleepablePreload {
		if sleepablePreload, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_preload", "sleepable_preload", attach); err != nil {
			return nil, err
		}
	}

	return un, err
}

func LoadUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Open:   UprobeOpen(load),
		Attach: UprobeAttach(load, bpfDir),
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
