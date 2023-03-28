package tracing

import (
	"errors"
	"fmt"
	"sync/atomic"

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
) (*sensors.Sensor, error) {

	spec := policy.TpSpec()
	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.KProbes) > 0 {
		name := fmt.Sprintf("gkp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		err := preValidateKprobes(name, spec.KProbes)
		if err != nil {
			return nil, err
		}
		return createGenericKprobeSensor(name, spec.KProbes, policyID)
	}
	if len(spec.Tracepoints) > 0 {
		name := fmt.Sprintf("gtp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createGenericTracepointSensor(name, spec.Tracepoints, policyID)
	}
	return nil, nil
}
