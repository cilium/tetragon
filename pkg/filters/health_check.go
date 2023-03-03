// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"context"
	"path"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	shell "github.com/kballard/go-shellquote"
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

func filterByHealthCheck(healthCheck bool) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		parent := GetParent(ev)
		if healthCheck {
			return canBeHealthCheck(process) || canBeHealthCheck(parent)
		}
		return !canBeHealthCheck(process) && !canBeHealthCheck(parent)
	}
}

type HealthCheckFilter struct{}

func (f *HealthCheckFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.HealthCheck != nil {
		fs = append(fs, filterByHealthCheck(ff.HealthCheck.Value))
	}
	return fs, nil
}
