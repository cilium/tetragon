// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type policyHandler struct{}

func init() {
	sensors.RegisterPolicyHandlerAtInit("tracing", policyHandler{})
}

func (h policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (sensors.SensorIface, error) {

	policyName := policy.TpName()
	spec := policy.TpSpec()

	namespace := ""
	if tpn, ok := policy.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpn.TpNamespace()
	}

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
	if sections > 1 {
		return nil, errors.New("tracing policies with multiple sections of kprobes, tracepoints, or lsm hooks are currently not supported")
	}

	handler := eventhandler.GetCustomEventhandler(policy)
	if len(spec.KProbes) > 0 {
		name := "generic_kprobe"
		err := preValidateKprobes(name, spec.KProbes, spec.Lists)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return createGenericKprobeSensor(spec, name, policyID, policyName, namespace, handler)
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(spec, "generic_tracepoint", policyID, policyName, namespace, handler)
	}
	if len(spec.LsmHooks) > 0 {
		return createGenericLsmSensor(spec, "generic_lsm", policyID, policyName, namespace)
	}
	if len(spec.UProbes) > 0 {
		return createGenericUprobeSensor(spec, "generic_lsm", policyName, namespace)
	}
	return nil, nil
}
