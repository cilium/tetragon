// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package syscallmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func rawSyscallName(_ *tetragon.ProcessTracepoint) string {
	return ""
}
