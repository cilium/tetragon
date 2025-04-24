// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func (h policyHandler) PolicyHandler(
	_ tracingpolicy.TracingPolicy,
	_ policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	return nil, constants.ErrWindowsNotSupported
}
