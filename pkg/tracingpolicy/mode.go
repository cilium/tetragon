// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TpModeToString(m tetragon.TracingPolicyMode) (string, error) {
	var mode string
	switch m {
	case tetragon.TracingPolicyMode_TP_MODE_ENFORCE:
		mode = "enforce"
	case tetragon.TracingPolicyMode_TP_MODE_MONITOR:
		mode = "monitor"
	default:
		return "", fmt.Errorf("invalid mode: %v", m)
	}
	return mode, nil
}

func TpStringToMode(s string) (tetragon.TracingPolicyMode, error) {
	var mode tetragon.TracingPolicyMode
	switch s {
	case "enforce":
		mode = tetragon.TracingPolicyMode_TP_MODE_ENFORCE
	case "monitor":
		mode = tetragon.TracingPolicyMode_TP_MODE_MONITOR
	default:
		return tetragon.TracingPolicyMode_TP_MODE_UNKNOWN, fmt.Errorf("invalid mode: %s", s)
	}
	return mode, nil
}
