// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package java

import (
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type policyHandler struct{}

func init() { sensors.RegisterPolicyHandlerAtInit("java", policyHandler{}) }

func (policyHandler) PolicyHandler(
	_ tracingpolicy.TracingPolicy,
	_ policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	return nil, nil
}
