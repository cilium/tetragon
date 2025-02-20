// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/enforcermetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type enforcerHandler struct {
	syscallsSyms []string
}

type enforcerPolicy struct {
	mu        sync.Mutex
	enforcers map[string]*enforcerHandler
}

func newEnforcerPolicy() *enforcerPolicy {
	return &enforcerPolicy{
		enforcers: map[string]*enforcerHandler{},
	}
}

var (
	// global enforcer policy
	gEnforcerPolicy = newEnforcerPolicy()
)

func init() {
	sensors.RegisterProbeType("enforcer", gEnforcerPolicy)
	sensors.RegisterPolicyHandlerAtInit("enforcer", gEnforcerPolicy)
}

func enforcerMapsUser(load *program.Program) []*program.Map {
	edm := program.MapUserPolicy(EnforcerDataMapName, load)
	edm.SetMaxEntries(enforcerMapMaxEntries)
	return []*program.Map{
		edm,
		program.MapUserPolicy(enforcermetrics.EnforcerMissedMapName, load),
	}
}

func enforcerMaps(load *program.Program) []*program.Map {
	edm := program.MapBuilderPolicy(EnforcerDataMapName, load)
	edm.SetMaxEntries(enforcerMapMaxEntries)
	return []*program.Map{
		edm,
		program.MapBuilderPolicy(enforcermetrics.EnforcerMissedMapName, load),
	}
}

func (kp *enforcerPolicy) enforcerGet(name string) (*enforcerHandler, bool) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kh, ok := kp.enforcers[name]
	return kh, ok
}

func (kp *enforcerPolicy) enforcerAdd(name string, kh *enforcerHandler) bool {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	if _, ok := kp.enforcers[name]; ok {
		return false
	}
	kp.enforcers[name] = kh
	return true
}

func (kp *enforcerPolicy) enforcerDel(name string) bool {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	if _, ok := kp.enforcers[name]; !ok {
		return false
	}
	delete(kp.enforcers, name)
	return true
}

func (kp *enforcerPolicy) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	_ policyfilter.PolicyID,
) (sensors.SensorIface, error) {

	spec := policy.TpSpec()

	if len(spec.Lists) > 0 {
		err := preValidateLists(spec.Lists)
		if err != nil {
			return nil, err
		}
	}

	if len(spec.Enforcers) > 0 {
		namespace := ""
		if tpn, ok := policy.(tracingpolicy.TracingPolicyNamespaced); ok {
			namespace = tpn.TpNamespace()
		}
		return kp.createEnforcerSensor(spec.Enforcers, spec.Lists, spec.Options, policy.TpName(), namespace)
	}

	return nil, nil
}

func (kp *enforcerPolicy) loadSingleEnforcerSensor(
	kh *enforcerHandler,
	bpfDir string, load *program.Program, maps []*program.Map, verbose int,
) error {
	if err := program.LoadKprobeProgramAttachMany(bpfDir, load, kh.syscallsSyms, maps, verbose); err == nil {
		logger.GetLogger().Infof("Loaded enforcer sensor: %s", load.Attach)
	} else {
		return err
	}
	return nil
}

func (kp *enforcerPolicy) loadMultiEnforcerSensor(
	kh *enforcerHandler,
	bpfDir string, load *program.Program, maps []*program.Map, verbose int,
) error {
	data := &program.MultiKprobeAttachData{}

	data.Symbols = append(data.Symbols, kh.syscallsSyms...)

	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, load, maps, verbose); err != nil {
		return err
	}

	logger.GetLogger().Infof("Loaded enforcer sensor: %s", load.Attach)
	return nil
}

func (kp *enforcerPolicy) LoadProbe(args sensors.LoadProbeArgs) error {
	name, ok := args.Load.LoaderData.(string)
	if !ok {
		return fmt.Errorf("invalid loadData type: expecting string and got: %T (%v)",
			args.Load.LoaderData, args.Load.LoaderData)
	}
	kh, ok := kp.enforcerGet(name)
	if !ok {
		return fmt.Errorf("failed to get enforcer handler for '%s'", name)
	}
	if args.Load.Label == "kprobe.multi/enforcer" {
		return kp.loadMultiEnforcerSensor(kh, args.BPFDir, args.Load, args.Maps, args.Verbose)
	}
	if args.Load.Label == "kprobe/enforcer" {
		return kp.loadSingleEnforcerSensor(kh, args.BPFDir, args.Load, args.Maps, args.Verbose)
	}

	if strings.HasPrefix(args.Load.Label, "fmod_ret/") {
		return program.LoadFmodRetProgram(args.BPFDir, args.Load, args.Maps, "fmodret_enforcer", args.Verbose)
	}

	return fmt.Errorf("enforcer loader: unknown label: %s", args.Load.Label)
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
			return OverrideMethodInvalid, fmt.Errorf("no override helper or mod_ret support: cannot load enforcer")
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

func (kp *enforcerPolicy) createEnforcerSensor(
	enforcers []v1alpha1.EnforcerSpec,
	lists []v1alpha1.ListSpec,
	opts []v1alpha1.OptionSpec,
	policyName string,
	policyNamespace string,
) (*sensors.Sensor, error) {

	if len(enforcers) > 1 {
		return nil, fmt.Errorf("failed: we support only single enforcer sensor")
	}

	enforcer := enforcers[0]

	var (
		hasSyscall  bool
		hasSecurity bool
	)

	kh := &enforcerHandler{}
	for _, call := range enforcer.Calls {
		var symsToAdd []string
		if isL, list := isList(call, lists); isL {
			if list == nil {
				return nil, fmt.Errorf("Error list '%s' not found", call)
			}
			switch list.Type {
			case "syscalls":
				syms, err := getSyscallListSymbols(list)
				if err != nil {
					return nil, err
				}
				hasSyscall = true
				// we know that this is a list of syscalls, so no need to check them
				kh.syscallsSyms = append(kh.syscallsSyms, syms...)
				continue
			default:
				// for everything else, we just append the symbols
				symsToAdd = list.Values
			}
		} else {
			symsToAdd = []string{call}
		}

		// check and add the rest of the symbols
		for _, sym := range symsToAdd {
			if arch.HasSyscallPrefix(sym) {
				hasSyscall = true
			} else if strings.HasPrefix(sym, "sys_") {
				hasSyscall = true
				var err error
				sym, err = arch.AddSyscallPrefix(sym)
				if err != nil {
					return nil, err
				}
			} else if strings.HasPrefix(sym, "security_") {
				hasSecurity = true
			} else {
				return nil, fmt.Errorf("enforcer sensor requires either syscall or security_ functions and symbol '%s' appears to be neither", sym)
			}
			kh.syscallsSyms = append(kh.syscallsSyms, sym)
		}
	}

	// register enforcer sensor
	var load *program.Program
	var progs []*program.Program
	var maps []*program.Map
	specOpts, err := getSpecOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get spec options: %s", err)
	}

	if !bpf.HasSignalHelper() {
		return nil, fmt.Errorf("enforcer sensor requires signal helper which is not available")
	}

	// select proper override method based on configuration and spec options
	overrideMethod := specOpts.OverrideMethod

	// we can't use override return for security_* functions (kernel limitation)
	// switch to fmod_ret and warn
	if hasSecurity && overrideMethod != OverrideMethodFmodRet {
		// fail if override-return is directly requested
		if overrideMethod == OverrideMethodReturn {
			return nil, fmt.Errorf("enforcer: can't override security function with override-return")
		}
		overrideMethod = OverrideMethodFmodRet
		logger.GetLogger().Infof("enforcer: forcing fmod_ret (security_* call detected)")
	}

	overrideMethod, err = selectOverrideMethod(overrideMethod, hasSyscall)
	if err != nil {
		return nil, err
	}

	switch overrideMethod {
	case OverrideMethodReturn:
		useMulti := !specOpts.DisableKprobeMulti && !option.Config.DisableKprobeMulti && bpf.HasKprobeMulti()
		logger.GetLogger().Infof("enforcer: using override return (multi-kprobe: %t)", useMulti)
		label := "kprobe/enforcer"
		prog := "bpf_enforcer.o"
		if useMulti {
			label = "kprobe.multi/enforcer"
			prog = "bpf_multi_enforcer.o"
		}
		attach := fmt.Sprintf("%d syscalls: %s", len(kh.syscallsSyms), kh.syscallsSyms)
		load = program.Builder(
			path.Join(option.Config.HubbleLib, prog),
			attach,
			label,
			"kprobe",
			"enforcer").
			SetLoaderData(policyName).
			SetPolicy(policyName)

		progs = append(progs, load)
		maps = append(maps, enforcerMaps(load)...)
	case OverrideMethodFmodRet:
		// for fmod_ret, we need one program per syscall
		logger.GetLogger().Infof("enforcer: using fmod_ret")
		for _, syscallSym := range kh.syscallsSyms {
			load = program.Builder(
				path.Join(option.Config.HubbleLib, "bpf_fmodret_enforcer.o"),
				syscallSym,
				"fmod_ret/security_task_prctl",
				fmt.Sprintf("fmod_ret_%s", syscallSym),
				"enforcer").
				SetLoaderData(policyName).
				SetPolicy(policyName)
			progs = append(progs, load)
			maps = append(maps, enforcerMaps(load)...)
		}
	default:
		return nil, fmt.Errorf("unexpected override method: %d", overrideMethod)
	}

	if ok := kp.enforcerAdd(policyName, kh); !ok {
		return nil, fmt.Errorf("failed to add enforcer: '%s'", policyName)
	}

	logger.GetLogger().Infof("Added enforcer sensor '%s'", policyName)

	return &sensors.Sensor{
		Name:      "__enforcer__",
		Progs:     progs,
		Maps:      maps,
		Policy:    policyName,
		Namespace: policyNamespace,
		DestroyHook: func() error {
			if ok := kp.enforcerDel(policyName); !ok {
				logger.GetLogger().Infof("Failed to clean up enforcer sensor '%s'", policyName)
			} else {
				logger.GetLogger().Infof("Cleaned up enforcer sensor '%s'", policyName)
			}
			return nil
		},
	}, nil
}
