// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type policyHandler struct{}

func init() {
	sensors.RegisterPolicyHandlerAtInit("tracing", policyHandler{})
}

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
		Index: 0,
		Name:  policyconf.PolicyConfMapName,
		Load: func(m *ebpf.Map, _ string, _ uint32) error {
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
