// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"github.com/cilium/tetragon/pkg/sensors"
)

type policyHandler struct{}

func init() {
	sensors.RegisterPolicyHandlerAtInit("tracing", policyHandler{})
}
