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

const (
	killerDataMapName = "killer_data"
)

type killerHandler struct {
	configured   bool
	syscallsSyms []string
}

func newKillerHandler() *killerHandler {
	return &killerHandler{
		configured: false,
	}
}

var (
	// global killer handler
	gKillerHandler = newKillerHandler()
)

func init() {
	sensors.RegisterProbeType("killer", gKillerHandler)
	sensors.RegisterPolicyHandlerAtInit("killer", gKillerHandler)
}

func (kh *killerHandler) PolicyHandler(
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
		return kh.createKillerSensor(spec.Killers, spec.Lists, spec.Options, name)
	}

	return nil, nil
}

func (kh *killerHandler) loadSingleKillerSensor(
	bpfDir, mapDir string, load *program.Program, verbose int,
) error {
	if err := program.LoadKprobeProgramAttachMany(bpfDir, mapDir, load, kh.syscallsSyms, verbose); err == nil {
		logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	} else {
		return err
	}
	return nil
}

func (kh *killerHandler) loadMultiKillerSensor(bpfDir, mapDir string, load *program.Program, verbose int) error {
	data := &program.MultiKprobeAttachData{}

	data.Symbols = append(data.Symbols, kh.syscallsSyms...)

	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	return nil
}

func (kh *killerHandler) LoadProbe(args sensors.LoadProbeArgs) error {
	if args.Load.Label == "kprobe.multi/killer" {
		return kh.loadMultiKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}
	if args.Load.Label == "kprobe/killer" {
		return kh.loadSingleKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}

	if strings.HasPrefix(args.Load.Label, "fmod_ret/") {
		return program.LoadFmodRetProgram(args.BPFDir, args.MapDir, args.Load, "fmodret_killer", args.Verbose)
	}

	return fmt.Errorf("killer loader: unknown label: %s", args.Load.Label)
}

// select proper override method based on configuration and spec options
func selectOverrideMethod(overrideMethod OverrideMethod, hasSyscall bool) (OverrideMethod, error) {
	switch overrideMethod {
	case OverrideMethodDefault:
		// by default, first try OverrideReturn and if this does not work try fmod_ret
		if bpf.HasOverrideHelper() {
			overrideMethod = OverrideMethodReturn
		} else if bpf.HasModifyReturnSyscall() {
			overrideMethod = OverrideMethodFmodRet
		} else {
			return OverrideMethodInvalid, fmt.Errorf("no override helper or mod_ret support: cannot load killer")
		}
	case OverrideMethodReturn:
		if !bpf.HasOverrideHelper() {
			return OverrideMethodInvalid, fmt.Errorf("option override return set, but it is not supported")
		}
	case OverrideMethodFmodRet:
		if !bpf.HasModifyReturn() || (hasSyscall && !bpf.HasModifyReturnSyscall()) {
			return OverrideMethodInvalid, fmt.Errorf("option fmod_ret set, but it is not supported")
		}
	}

	return overrideMethod, nil
}

func (kh *killerHandler) unload() error {
	kh.configured = false
	kh.syscallsSyms = []string{}
	logger.GetLogger().Infof("Cleaning up killer")
	return nil
}

func (kh *killerHandler) createKillerSensor(
	killers []v1alpha1.KillerSpec,
	lists []v1alpha1.ListSpec,
	opts []v1alpha1.OptionSpec,
	name string,
) (*sensors.Sensor, error) {

	if len(killers) > 1 {
		return nil, fmt.Errorf("failed: we support only single killer sensor")
	}

	if kh.configured {
		return nil, fmt.Errorf("failed: killer sensor is already configured")
	}
	kh.configured = true

	killer := killers[0]

	var (
		hasSyscall  bool
		hasSecurity bool
	)

	// get all the syscalls
	for idx := range killer.Calls {
		sym := killer.Calls[idx]
		if strings.HasPrefix(sym, "list:") {
			listName := sym[len("list:"):]

			list := getList(listName, lists)
			if list == nil {
				return nil, fmt.Errorf("Error list '%s' not found", listName)
			}

			kh.syscallsSyms = append(kh.syscallsSyms, list.Values...)
			continue
		}

		kh.syscallsSyms = append(kh.syscallsSyms, sym)
	}

	var err error

	// fix syscalls
	for idx, sym := range kh.syscallsSyms {
		isPrefix := arch.HasSyscallPrefix(sym)
		isSyscall := strings.HasPrefix(sym, "sys_")
		isSecurity := strings.HasPrefix(sym, "security_")

		if !isSyscall && !isSecurity && !isPrefix {
			return nil, fmt.Errorf("killer sensor requires either syscall or security_ functions")
		}

		if isSyscall {
			sym, err = arch.AddSyscallPrefix(sym)
			if err != nil {
				return nil, err
			}
			kh.syscallsSyms[idx] = sym
		}

		hasSyscall = hasSyscall || isSyscall || isPrefix
		hasSecurity = hasSecurity || isSecurity
	}

	// register killer sensor
	var load *program.Program
	var progs []*program.Program
	var maps []*program.Map
	specOpts, err := getSpecOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get spec options: %s", err)
	}

	if !bpf.HasSignalHelper() {
		return nil, fmt.Errorf("killer sensor requires signal helper which is not available")
	}

	// select proper override method based on configuration and spec options
	overrideMethod := specOpts.OverrideMethod

	// we can't use override return for security_* functions (kernel limitation)
	// switch to fmod_ret and warn
	if hasSecurity && overrideMethod != OverrideMethodFmodRet {
		// fail if override-return is directly requested
		if overrideMethod == OverrideMethodReturn {
			return nil, fmt.Errorf("killer: can't override security function with override-return")
		}
		overrideMethod = OverrideMethodFmodRet
		logger.GetLogger().Infof("killer: forcing fmod_ret (security_* call detected)")
	}

	overrideMethod, err = selectOverrideMethod(overrideMethod, hasSyscall)
	if err != nil {
		return nil, err
	}

	pinPath := sensors.PathJoin(name, "killer_kprobe")
	switch overrideMethod {
	case OverrideMethodReturn:
		useMulti := !specOpts.DisableKprobeMulti && !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()
		logger.GetLogger().Infof("killer: using override return (multi-kprobe: %t)", useMulti)
		label := "kprobe/killer"
		prog := "bpf_killer.o"
		if useMulti {
			label = "kprobe.multi/killer"
			prog = "bpf_multi_killer.o"
		}
		attach := fmt.Sprintf("%d syscalls: %s", len(kh.syscallsSyms), kh.syscallsSyms)
		load = program.Builder(
			path.Join(option.Config.HubbleLib, prog),
			attach,
			label,
			pinPath,
			"killer")
		progs = append(progs, load)
	case OverrideMethodFmodRet:
		// for fmod_ret, we need one program per syscall
		logger.GetLogger().Infof("killer: using fmod_ret")
		for _, syscallSym := range kh.syscallsSyms {
			load = program.Builder(
				path.Join(option.Config.HubbleLib, "bpf_fmodret_killer.o"),
				syscallSym,
				"fmod_ret/security_task_prctl",
				pinPath,
				"killer")
			progs = append(progs, load)
		}
	default:
		return nil, fmt.Errorf("unexpected override method: %d", overrideMethod)
	}

	killerDataMap := program.MapBuilderPin(killerDataMapName, killerDataMapName, load)
	maps = append(maps, killerDataMap)

	return &sensors.Sensor{
		Name:           "__killer__",
		Progs:          progs,
		Maps:           maps,
		PostUnloadHook: gKillerHandler.unload,
	}, nil
}
