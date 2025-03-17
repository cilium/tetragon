// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/program/cgroup"
)

var (
	// list of registered policy handlers, see RegisterPolicyHandlerAtInit()
	registeredPolicyHandlers = map[string]policyHandler{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad = map[string]probeLoader{}
	standardTypes       = map[string]func(string, *program.Program, []*program.Map, int) error{
		"tracepoint":     program.LoadTracepointProgram,
		"raw_tracepoint": program.LoadRawTracepointProgram,
		"raw_tp":         program.LoadRawTracepointProgram,
		"cgrp_socket":    cgroup.LoadCgroupProgram,
		"kprobe":         program.LoadKprobeProgram,
		"lsm":            program.LoadLSMProgram,
	}
)
