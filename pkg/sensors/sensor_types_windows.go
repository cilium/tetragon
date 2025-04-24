// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	// list of registered policy handlers, see RegisterPolicyHandlerAtInit()
	registeredPolicyHandlers = map[string]policyHandler{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad = map[string]probeLoader{}
	standardTypes       = map[string]func(string, *program.Program, []*program.Map, int) error{
		"windows": program.LoadWindowsProgram,
	}
)
