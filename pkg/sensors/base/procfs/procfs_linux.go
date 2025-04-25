// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procfs

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/utils"
)

func init() {
	loader := procWalkerLoader{}
	sensors.RegisterProbeType(CGROUP_FENTRY_TYPE, &loader)
}

var (
	CgroupLookupKprobe = program.Builder(
		"bpf_cgroup_lookup.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"kprobe",
	)

	CgroupLookupFentry = program.Builder(
		"bpf_cgroup_lookup_fentry.o",
		"proc_task_name",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		CGROUP_FENTRY_TYPE,
	)

	NsidMapKprobe = program.MapBuilder("tg_cgroup_namespace_map", CgroupLookupKprobe)
	NsidMapFentry = program.MapBuilder("tg_cgroup_namespace_map", CgroupLookupFentry)
)

const CGROUP_FENTRY_TYPE = "cgroup_fentry"

type procWalkerLoader struct{}

func (loader *procWalkerLoader) LoadProbe(args sensors.LoadProbeArgs) error {
	var err error
	switch args.Load.Type {
	case CGROUP_FENTRY_TYPE:
		err = program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
	}
	return err
}

func Enable() (progs []*program.Program, maps []*program.Map) {
	// Not supported on kernels < 5.4
	if kernels.IsKernelVersionLessThan("5.4") {
		return progs, maps
	}
	if utils.SupportFentry() {
		progs = append(progs, CgroupLookupFentry)
		maps = append(maps, NsidMapFentry)
	} else {
		progs = append(progs, CgroupLookupKprobe)
		maps = append(maps, NsidMapKprobe)
	}
	return progs, maps
}

// Walk walks procfs and reads comm for every pid. This is done to trigger
// a BPF program that pre-populates the cgroup -> nsid map on the BPF side.
func Walk() error {
	dentries, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		return err
	}
	for _, entry := range dentries {
		// We only care about numeric directories (per-pid)
		if _, err := strconv.Atoi(entry.Name()); err != nil || !entry.IsDir() {
			continue
		}
		if err := readComm(entry.Name()); err != nil {
			logger.GetLogger().WithError(err).WithFields(map[string]any{
				"pid":    entry.Name(),
				"procfs": option.Config.ProcFS,
			}).Debug("base: failed to read comm during procfs walk")
		}
	}
	return nil
}

// readComm reads the comm for a pid in procfs and discards the result.
func readComm(pidEntry string) error {
	_, err := os.ReadFile(filepath.Join(option.Config.ProcFS, pidEntry, "comm"))
	return err
}
