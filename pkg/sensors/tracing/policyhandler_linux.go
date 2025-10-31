// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/policystats"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	// should be enough for most use cases
	cgroupToPolicyMapMaxEntries = 32768
	// should be enough for most use cases
	policyStringHashMapsMaxEntries = 32768
	// seems a reasonable default for now
	innerPolicyStringMapMaxEntries = 200
)

type policyInfo struct {
	name          string
	namespace     string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
	policyConf    *program.Map
	policyStats   *program.Map
	specOpts      *specOptions

	cgroupToPolicy   *program.Map
	policyStringHash []*program.Map
	isTemplate       bool
}

func newPolicyInfo(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (*policyInfo, error) {
	namespace := ""
	if tpn, ok := policy.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpn.TpNamespace()
	}

	return newPolicyInfoFromSpec(
		namespace,
		policy.TpName(),
		policyID,
		policy.TpSpec(),
		eventhandler.GetCustomEventhandler(policy),
	)

}

func newPolicyInfoFromSpec(
	namespace, name string,
	policyID policyfilter.PolicyID,
	spec *v1alpha1.TracingPolicySpec,
	customHandler eventhandler.Handler,
) (*policyInfo, error) {
	opts, err := getSpecOptions(spec.Options)
	if err != nil {
		return nil, err
	}
	return &policyInfo{
		name:          name,
		namespace:     namespace,
		policyID:      policyID,
		customHandler: customHandler,
		policyConf:    nil,
		policyStats:   nil,
		specOpts:      opts,
		isTemplate:    sensors.IsTracingPolicyTemplate(spec.Options),
	}, nil
}

func (pi *policyInfo) policyStatsMap(prog *program.Program) *program.Map {
	if pi.policyStats != nil {
		return program.MapUserFrom(pi.policyStats)
	}
	pi.policyStats = program.MapBuilderPolicy(policystats.PolicyStatsMapName, prog)
	return pi.policyStats
}

func (pi *policyInfo) cgroupToPolicyMap(prog *program.Program) *program.Map {
	if pi.cgroupToPolicy != nil {
		return program.MapUserFrom(pi.cgroupToPolicy)
	}

	pi.cgroupToPolicy = program.MapBuilderPolicy(sensors.CgroupToPolicyMapName, prog)
	// we bump the entry only if the policy is a template since this is the only case in which this map is used.
	if pi.isTemplate {
		pi.cgroupToPolicy.SetMaxEntries(cgroupToPolicyMapMaxEntries)
	}
	return pi.cgroupToPolicy
}

func (pi *policyInfo) policyStringHashMaps(prog *program.Program) []*program.Map {
	if len(pi.policyStringHash) != 0 {
		userMaps := make([]*program.Map, 0, len(pi.policyStringHash))
		for _, m := range pi.policyStringHash {
			userMaps = append(userMaps, program.MapUserFrom(m))
		}
		return userMaps
	}

	numSubMaps := selectors.StringMapsNumSubMaps
	if !kernels.MinKernelVersion("5.11") {
		numSubMaps = selectors.StringMapsNumSubMapsSmall
	}
	pi.policyStringHash = make([]*program.Map, 0, numSubMaps)

	for stringMapIndex := range numSubMaps {
		policyStrMap := program.MapBuilderPolicy(fmt.Sprintf("%s_%d", sensors.PolicyStringHashMapPrefix, stringMapIndex), prog)
		pi.policyStringHash = append(pi.policyStringHash, policyStrMap)

		// there is no reason to bump dimensions, these maps will be never used. So we leave max_entries to 1.
		if !pi.isTemplate {
			continue
		}

		policyStrMap.SetMaxEntries(policyStringHashMapsMaxEntries)
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			//
			// In this case we put a fixed size for internal maps and we will use BPF_F_NO_PREALLOC when we create them.
			// Otherwise internal maps will have real sizes according to the number of entries we need.
			policyStrMap.SetInnerMaxEntries(innerPolicyStringMapMaxEntries)
		}
	}
	return pi.policyStringHash
}

func (pi *policyInfo) policyConfMap(prog *program.Program) *program.Map {
	if pi.policyConf != nil {
		return program.MapUserFrom(pi.policyConf)
	}
	pi.policyConf = program.MapBuilderPolicy(policyconf.PolicyConfMapName, prog)
	prog.MapLoad = append(prog.MapLoad, &program.MapLoad{
		Name: policyconf.PolicyConfMapName,
		Load: func(m *ebpf.Map, _ string) error {
			mode := policyconf.EnforceMode
			if pi.specOpts != nil {
				mode = pi.specOpts.policyMode
			}
			conf := policyconf.PolicyConf{
				Mode: mode,
			}
			key := uint32(0)
			return m.Update(key, &conf, ebpf.UpdateAny)
		},
	})
	return pi.policyConf
}

func (h policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (sensors.SensorIface, error) {

	spec := policy.TpSpec()
	sections := 0
	if len(spec.KProbes) > 0 {
		sections++
	}
	if len(spec.Tracepoints) > 0 {
		sections++
	}
	if len(spec.LsmHooks) > 0 {
		sections++
	}
	if len(spec.UProbes) > 0 {
		sections++
	}
	if len(spec.Usdts) > 0 {
		sections++
	}
	if sections > 1 {
		return nil, errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, uprobes or usdts are currently not supported")
	}

	polInfo, err := newPolicyInfo(policy, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if len(spec.KProbes) > 0 {
		name := "generic_kprobe"
		log := logger.GetLogger().With(
			"policy", tracingpolicy.TpLongname(policy),
			"sensor", name,
		)
		validateInfo, err := preValidateKprobes(log, spec.KProbes, spec.Lists, spec.Enforcers)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		// if all kprobes where ignored, do not load anything. This is equivalent with
		// having a policy with an empty kprobe: section
		if allKprobesIgnored(validateInfo) {
			return nil, nil
		}
		return createGenericKprobeSensor(spec, name, polInfo, validateInfo)
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(spec, "generic_tracepoint", polInfo)
	}
	if len(spec.LsmHooks) > 0 {
		return createGenericLsmSensor(spec, "generic_lsm", polInfo)
	}
	if len(spec.UProbes) > 0 {
		return createGenericUprobeSensor(spec, "generic_uprobe", polInfo)
	}
	if len(spec.Usdts) > 0 {
		return createGenericUsdtSensor(spec, "generic_usdt", polInfo)
	}
	return nil, nil
}
