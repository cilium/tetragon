package program

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	cachedbtf "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

var (
	verifierLogBufferSize = 10 * 1024 * 1024 // 10MB
)

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Program, *ebpf.ProgramSpec) (unloader.Unloader, error)

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

func LoadProgram(
	bpfDir string,
	mapDirs []string,
	load *Program,
	withProgram AttachFunc,
) error {
	var btfSpec *btf.Spec
	if btfFilePath := cachedbtf.GetCachedBTFFile(); btfFilePath != "/sys/kernel/btf/vmlinux" {
		// Non-standard path to BTF, open it and provide it as 'KernelTypes'.
		var err error
		btfSpec, err = btf.LoadSpec(btfFilePath)
		if err != nil {
			return fmt.Errorf("opening BTF file '%s' failed: %w", btfFilePath, err)
		}
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
		if inst.Reference() != "" {
			refMaps[inst.Reference()] = true
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

	var opts ebpf.CollectionOptions
	if btfSpec != nil {
		opts.Programs.KernelTypes = btfSpec
	}

	opts.MapReplacements = pinnedMaps

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
