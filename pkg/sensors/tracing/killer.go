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
		return createKillerSensor(spec.Killers, spec.Lists, name)
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

	for idx := range syscallsSyms {
		data.Symbols = append(data.Symbols, syscallsSyms[idx])
	}

	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	return nil
}

func (k *killerSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if args.Load.Label == "kprobe/killer" {
		return loadSingleKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}
	return loadMultiKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
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

	useMulti := !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()

	attach := fmt.Sprintf("%d syscalls: %s", len(syscallsSyms), syscallsSyms)
	prog := sensors.PathJoin(name, "killer_kprobe")

	if useMulti {
		load = program.Builder(
			path.Join(option.Config.HubbleLib, "bpf_multi_killer.o"),
			attach,
			"kprobe.multi/killer",
			prog,
			"killer")

	} else {
		load = program.Builder(
			path.Join(option.Config.HubbleLib, "bpf_killer.o"),
			attach,
			"kprobe/killer",
			prog,
			"killer")
	}

	killerDataMap := program.MapBuilderPin("killer_data", "killer_data", load)

	progs = append(progs, load)
	maps = append(maps, killerDataMap)

	return &sensors.Sensor{
		Name:           "__killer__",
		Progs:          progs,
		Maps:           maps,
		PostUnloadHook: unloadKiller,
	}, nil
}
