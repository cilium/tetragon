// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

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
	if sections > 1 {
		return nil, errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, or uprobes are currently not supported")
	}

	polInfo, err := newPolicyInfo(policy, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if len(spec.KProbes) > 0 {
		name := "generic_kprobe"
		err := preValidateKprobes(name, spec.KProbes, spec.Lists)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return createGenericKprobeSensor(spec, name, polInfo)
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
	return nil, nil
}
