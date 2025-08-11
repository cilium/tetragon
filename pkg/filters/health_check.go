// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"path"

	shell "github.com/kballard/go-shellquote"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func MaybeExecProbe(binary string, args string, execProbe []string) bool {
	// If the exec probe is empty for whatever reason, return false.
	if len(execProbe) == 0 {
		return false
	}
	argList, err := shell.Split(args)
	if err != nil {
		return false
	}

	// Exec will append a script name to argument list if a sh/bash script is executed with a shebang,
	// so we need to remove the first argument so that we can compare it to execProbe.
	// e.g.
	// "binary": "/health/ping_liveness_local.sh",
	// "arguments": "/health/ping_liveness_local.sh 5"
	// concatenated together will be ["/health/ping_liveness_local.sh", "/health/ping_liveness_local.sh", "5"],
	// but execProbe will have only ["/health/ping_liveness_local.sh", "5"].
	if execProbe[0] == binary && len(argList) > 0 && argList[0] == binary {
		argList = argList[1:]
	}

	processCommand := append([]string{binary}, argList...)
	if len(execProbe) != len(processCommand) {
		return false
	}

	if path.IsAbs(execProbe[0]) {
		// exec probe path is absolute. Compare the full paths.
		if processCommand[0] != execProbe[0] {
			return false
		}
	} else {
		// exec probe path is relative. Only compare the basenames.
		if path.Base(processCommand[0]) != path.Base(execProbe[0]) {
			return false
		}
	}
	for i := 1; i < len(execProbe); i++ {
		if execProbe[i] != processCommand[i] {
			return false
		}
	}
	return true
}

func canBeHealthCheck(process *tetragon.Process) bool {
	return process != nil && process.Pod != nil && process.Pod.Container != nil && process.Pod.Container.MaybeExecProbe
}

func filterByHealthCheck(healthCheck bool) FilterFunc {
	return func(ev *event.Event) bool {
		process := GetProcess(ev)
		parent := GetParent(ev)
		if healthCheck {
			return canBeHealthCheck(process) || canBeHealthCheck(parent)
		}
		return !canBeHealthCheck(process) && !canBeHealthCheck(parent)
	}
}

type HealthCheckFilter struct{}

func (f *HealthCheckFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.HealthCheck != nil {
		fs = append(fs, filterByHealthCheck(ff.HealthCheck.Value))
	}
	return fs, nil
}
