// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func (h policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	return nil, errors.New("not supported on windows")
}
