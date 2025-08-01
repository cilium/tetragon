// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type policyInfo struct {
	name          string
	namespace     string
	policyID      policyfilter.PolicyID
	customHandler eventhandler.Handler
	policyConf    *program.Map
	specOpts      *specOptions
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
		specOpts:      opts,
	}, nil
}

func (pi *policyInfo) policyConfMap(prog *program.Program) *program.Map {
	if pi.policyConf != nil {
		return program.MapUserFrom(pi.policyConf)
	}
	pi.policyConf = program.MapBuilderPolicy("policy_conf", prog)
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
		return nil, errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, or uprobes are currently not supported")
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
		validateInfo, err := preValidateKprobes(log, spec.KProbes, spec.Lists)
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
