// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
	"sync/atomic"

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
		name := fmt.Sprintf("gkp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		err := preValidateKprobes(name, spec.KProbes, spec.Lists)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return createGenericKprobeSensor(spec, name, policyID, policyName, handler)
	}
	if len(spec.Tracepoints) > 0 {
		name := fmt.Sprintf("gtp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createGenericTracepointSensor(spec, name, policyID, policyName, handler)
	}
	if len(spec.LsmHooks) > 0 {
		name := fmt.Sprintf("glsm-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createGenericLsmSensor(spec, name, policyID, policyName)
	}
	return nil, nil
}
