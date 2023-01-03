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
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
	"golang.org/x/sys/unix"
)

var (
	verifierLogBufferSize = 10 * 1024 * 1024 // 10MB
)

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Program, *ebpf.ProgramSpec) (unloader.Unloader, error)

type customInstall struct {
	mapName   string
	secPrefix string
}

func RawAttach(targetFD int) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  targetFD,
			Program: prog,
			Attach:  spec.AttachType,
		})
		if err != nil {
			prog.Close()
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return unloader.ChainUnloader{
			unloader.PinUnloader{
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

func TracepointAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		parts := strings.Split(load.Attach, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("tracepoint attach argument must be in the form category/tracepoint, got: %s", load.Attach)
		}
		tpLink, err := link.Tracepoint(parts[0], parts[1], prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.PinUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       tpLink,
			RelinkFn: func() (link.Link, error) {
				return link.Tracepoint(parts[0], parts[1], prog, nil)
			},
		}, nil
	}
}

func RawTracepointAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
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
			unloader.PinUnloader{
				Prog: prog,
			},
			unloader.LinkUnloader{
				Link: lnk,
			},
		}, nil
	}
}

func KprobeAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		var linkFn func() (link.Link, error)

		if load.RetProbe {
			linkFn = func() (link.Link, error) { return link.Kretprobe(load.Attach, prog, nil) }
		} else {
			linkFn = func() (link.Link, error) { return link.Kprobe(load.Attach, prog, nil) }
		}

		lnk, err := linkFn()
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.PinUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       lnk,
			RelinkFn:   linkFn,
		}, nil
	}
}

func UprobeAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		data, ok := load.AttachData.(*UprobeAttachData)
		if !ok {
			return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
		}

		linkFn := func() (link.Link, error) {
			exec, err := link.OpenExecutable(data.Path)
			if err != nil {
				return nil, err
			}
			return exec.Uprobe(data.Symbol, prog, nil)
		}

		lnk, err := linkFn()
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return &unloader.RelinkUnloader{
			UnloadProg: unloader.PinUnloader{Prog: prog}.Unload,
			IsLinked:   true,
			Link:       lnk,
			RelinkFn:   linkFn,
		}, nil
	}
}

func NoAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return unloader.ChainUnloader{
			unloader.PinUnloader{
				Prog: prog,
			},
		}, nil
	}
}

func MultiKprobeAttach(load *Program) AttachFunc {
	return func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		data, ok := load.AttachData.(*MultiKprobeAttachData)
		if !ok {
			return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
		}
		opts := link.KprobeMultiOptions{
			Symbols: data.Symbols,
			Cookies: data.Cookies,
		}

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
		return unloader.ChainUnloader{
			unloader.PinUnloader{
				Prog: prog,
			},
			unloader.LinkUnloader{
				Link: lnk,
			},
		}, nil
	}
}

func LoadTracepointProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	var ci *customInstall
	for mName, mPath := range load.PinMap {
		if mName == "tp_calls" || mName == "execve_calls" {
			ci = &customInstall{mPath, "tracepoint"}
			break
		}
	}
	return loadProgram(bpfDir, []string{mapDir}, load, TracepointAttach(load), ci, verbose)
}

func LoadRawTracepointProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	return loadProgram(bpfDir, []string{mapDir}, load, RawTracepointAttach(load), nil, verbose)
}

func LoadKprobeProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	var ci *customInstall
	for mName, mPath := range load.PinMap {
		if mName == "kprobe_calls" {
			ci = &customInstall{mPath, "kprobe"}
			break
		}
	}
	return loadProgram(bpfDir, []string{mapDir}, load, KprobeAttach(load), ci, verbose)
}

func LoadUprobeProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	var ci *customInstall
	for mName, mPath := range load.PinMap {
		if mName == "uprobe_calls" {
			ci = &customInstall{mPath, "uprobe"}
			break
		}
	}
	return loadProgram(bpfDir, []string{mapDir}, load, UprobeAttach(load), ci, verbose)
}

func LoadTailCallProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	return loadProgram(bpfDir, []string{mapDir}, load, NoAttach(load), nil, verbose)
}

func LoadMultiKprobeProgram(bpfDir, mapDir string, load *Program, verbose int) error {
	ci := &customInstall{fmt.Sprintf("%s-kp_calls", load.PinPath), "kprobe"}
	return loadProgram(bpfDir, []string{mapDir}, load, MultiKprobeAttach(load), ci, verbose)
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

func installTailCalls(mapDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection, ci *customInstall) error {
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

		for i := 0; i < 11; i++ {
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
	if ci != nil {
		if err := install(ci.mapName, ci.secPrefix); err != nil {
			return err
		}
	}

	return nil
}

func doLoadProgram(
	bpfDir string,
	mapDirs []string,
	load *Program,
	withProgram AttachFunc,
	ci *customInstall,
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
		for _, mapDir := range mapDirs {
			var mapPath string
			if pinName, ok := load.PinMap[name]; ok {
				mapPath = filepath.Join(mapDir, pinName)
			} else {
				mapPath = filepath.Join(mapDir, name)
			}
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

	var opts ebpf.CollectionOptions
	if btfSpec != nil {
		opts.Programs.KernelTypes = btfSpec
	}

	opts.MapReplacements = pinnedMaps

	// Disable loading of override program if it's not needed
	if !load.Override {
		progOverrideSpec, ok := spec.Programs["generic_kprobe_override"]
		if ok {
			progOverrideSpec.Type = ebpf.UnspecifiedProgram
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		// Retry again with logging to capture the verifier log. We don't log by default
		// as that makes the loading very slow.
		opts.Programs.LogLevel = 1
		opts.Programs.LogSize = verifierLogBufferSize
		// If we hit ENOSPC that means that our log size is not big enough,
		// so keep trying again with log size * 2 until we succeed or the kernel
		// complains.
		for {
			coll, err = ebpf.NewCollectionWithOptions(spec, opts)
			if errors.Is(err, unix.ENOSPC) {
				opts.Programs.LogSize = opts.Programs.LogSize * 2
				continue
			}
			break
		}
		if err != nil {
			// Log the error directly using the logger so that the verifier log
			// gets properly pretty-printed.
			if verbose != 0 {
				logger.GetLogger().Infof("Opening collection failed, dumping verifier log.")
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					// Print a truncated version if we have verbose=1, otherwise dump the
					// full log.
					if verbose < 2 {
						fmt.Println(slimVerifierError(fmt.Sprintf("%+v", ve)))
					} else {
						fmt.Println(fmt.Sprintf("%+v", ve))
					}
				}
			}

			return nil, fmt.Errorf("opening collection '%s' failed: %w", load.Name, err)
		}
	}
	defer coll.Close()

	err = installTailCalls(mapDirs[0], spec, coll, ci)
	if err != nil {
		return nil, fmt.Errorf("installing tail calls failed: %s", err)
	}

	for _, mapLoad := range load.MapLoad {
		if m, ok := coll.Maps[mapLoad.Name]; ok {
			if err := mapLoad.Load(m, mapLoad.Index); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("populating map failed as map '%s' was not found from collection", mapLoad.Name)
		}
	}

	if load.Override {
		progOverrideSpec, ok := spec.Programs["generic_kprobe_override"]
		if ok {
			progOverrideSpec.Type = ebpf.UnspecifiedProgram
		}

		progOverride, ok := coll.Programs["generic_kprobe_override"]
		if !ok {
			return nil, fmt.Errorf("program for section '%s' not found", load.Label)
		}

		progOverride, err = progOverride.Clone()
		if err != nil {
			return nil, fmt.Errorf("failed to clone program '%s': %w", load.Label, err)
		}

		pinPath := filepath.Join(bpfDir, fmt.Sprint(load.PinPath, "-override"))

		if err := progOverride.Pin(pinPath); err != nil {
			return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
		}

		load.unloaderOverride, err = withProgram(progOverride, progOverrideSpec)
		if err != nil {
			logger.GetLogger().Warnf("Failed to attach override program: %w", err)
		}
	}

	prog, ok := coll.Programs[progSpec.Name]
	if !ok {
		return nil, fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath)

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

	load.unloader, err = withProgram(prog, progSpec)
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %w", pinPath, err)
		}
		return nil, err
	}

	// Copy the loaded collection before it's destroyed
	if KeepCollection {
		return copyLoadedCollection(coll)
	}
	return nil, nil
}

func loadProgram(
	bpfDir string,
	mapDirs []string,
	load *Program,
	withProgram AttachFunc,
	ci *customInstall,
	verbose int,
) error {
	lc, err := doLoadProgram(bpfDir, mapDirs, load, withProgram, ci, verbose)
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
	mapDirs []string,
	load *Program,
	withProgram AttachFunc,
	verbose int,
) error {
	return loadProgram(bpfDir, mapDirs, load, withProgram, nil, verbose)
}
