// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type killerSensor struct{}

func init() {
	killer := &killerSensor{}
	sensors.RegisterProbeType("killer", killer)
	sensors.RegisterPolicyHandlerAtInit("killer", killerSensor{})
}

var (
	configured   = false
	syscallsSyms []string
)

func (k killerSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	_ policyfilter.PolicyID,
) (*sensors.Sensor, error) {

	spec := policy.TpSpec()

	if len(spec.Lists) > 0 {
		err := preValidateLists(spec.Lists)
		if err != nil {
			return nil, err
		}
	}
	if len(spec.Killers) > 0 {
		name := fmt.Sprintf("killer-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createKillerSensor(spec.Killers, spec.Lists, spec.Options, name)
	}

	return nil, nil
}

func loadSingleKillerSensor(bpfDir, mapDir string, load *program.Program, verbose int) error {
	if err := program.LoadKprobeProgramAttachMany(bpfDir, mapDir, load, syscallsSyms, verbose); err == nil {
		logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	} else {
		return err
	}

	return nil
}

func loadMultiKillerSensor(bpfDir, mapDir string, load *program.Program, verbose int) error {
	data := &program.MultiKprobeAttachData{}

	data.Symbols = append(data.Symbols, syscallsSyms...)

	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	return nil
}

func (k *killerSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if args.Load.Label == "kprobe.multi/killer" {
		return loadMultiKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}
	if args.Load.Label == "kprobe/killer" {
		return loadSingleKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}

	if strings.HasPrefix(args.Load.Label, "fmod_ret/") {
		return program.LoadFmodRetProgram(args.BPFDir, args.MapDir, args.Load, "fmodret_killer", args.Verbose)
	}

	return fmt.Errorf("killer loader: unknown label: %s", args.Load.Label)
}

func unloadKiller() error {
	configured = false
	syscallsSyms = []string{}
	logger.GetLogger().Infof("Cleaning up killer")
	return nil
}

func createKillerSensor(
	killers []v1alpha1.KillerSpec,
	lists []v1alpha1.ListSpec,
	opts []v1alpha1.OptionSpec,
	name string,
) (*sensors.Sensor, error) {

	if len(killers) > 1 {
		return nil, fmt.Errorf("failed: we support only single killer sensor")
	}

	if configured {
		return nil, fmt.Errorf("failed: killer sensor is already configured")
	}

	configured = true

	killer := killers[0]

	// get all the syscalls
	for idx := range killer.Syscalls {
		sym := killer.Syscalls[idx]
		if strings.HasPrefix(sym, "list:") {
			listName := sym[len("list:"):]

			list := getList(listName, lists)
			if list == nil {
				return nil, fmt.Errorf("Error list '%s' not found", listName)
			}

			if !isSyscallListType(list.Type) {
				return nil, fmt.Errorf("Error list '%s' is not syscall type", listName)
			}
			syscallsSyms = append(syscallsSyms, list.Values...)
			continue
		}

		pfxSym, err := arch.AddSyscallPrefix(sym)
		if err != nil {
			return nil, err
		}
		syscallsSyms = append(syscallsSyms, pfxSym)
	}

	// register killer sensor
	var load *program.Program
	var progs []*program.Program
	var maps []*program.Map
	var useMulti bool

	specOpts, err := getSpecOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get spec options: %s", err)
	}

	if !specOpts.DisableKprobeMulti {
		useMulti = !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()
	}

	if !bpf.HasSignalHelper() {
		return nil, fmt.Errorf("killer sensor requires signal helper which is not available")
	}

	prog := sensors.PathJoin(name, "killer_kprobe")
	if bpf.HasOverrideHelper() {
		attach := fmt.Sprintf("%d syscalls: %s", len(syscallsSyms), syscallsSyms)
		label := "kprobe/killer"
		prog := "bpf_killer.o"
		if useMulti {
			label = "kprobe.multi/killer"
			prog = "bpf_multi_killer.o"
		}
		load = program.Builder(
			path.Join(option.Config.HubbleLib, prog),
			attach,
			label,
			prog,
			"killer")
		progs = append(progs, load)
	} else if bpf.HasModifyReturn() {
		// for fmod_ret, we need one program per syscall
		for _, syscallSym := range syscallsSyms {
			load = program.Builder(
				path.Join(option.Config.HubbleLib, "bpf_fmodret_killer.o"),
				syscallSym,
				"fmod_ret/security_task_prctl",
				prog,
				"killer")
			progs = append(progs, load)
		}
	} else {
		return nil, fmt.Errorf("no override helper or override support: cannot load killer")
	}

	killerDataMap := program.MapBuilderPin("killer_data", "killer_data", load)
	maps = append(maps, killerDataMap)

	return &sensors.Sensor{
		Name:           "__killer__",
		Progs:          progs,
		Maps:           maps,
		PostUnloadHook: unloadKiller,
	}, nil
}
