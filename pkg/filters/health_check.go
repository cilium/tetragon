// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"path"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

// JoinArgs joins process arguments into the form used for Process.Arguments.
// Arguments containing spaces are wrapped in double quotes.
func JoinArgs(args []string) string {
	var b strings.Builder
	for _, a := range args {
		if strings.Contains(a, " ") {
			b.WriteString(` "`)
			b.WriteString(a)
			b.WriteByte('"')
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a)
	}
	return b.String()
}

func MaybeExecProbe(binary string, args string, execProbe []string) bool {
	// If the exec probe is empty for whatever reason, return false.
	if len(execProbe) == 0 {
		return false
	}

	if path.IsAbs(execProbe[0]) {
		// exec probe path is absolute. Compare the full paths.
		if binary != execProbe[0] {
			return false
		}
	} else {
		// exec probe path is relative. Only compare the basenames.
		if path.Base(binary) != path.Base(execProbe[0]) {
			return false
		}
	}

	// args is lossy, so encode the probe the same way instead of parsing args.
	if args == JoinArgs(execProbe[1:]) {
		return true
	}

	// Exec will append a script name to argument list if a sh/bash script is executed with a shebang,
	// so we need to account for it when comparing to execProbe.
	// e.g.
	// "binary": "/health/ping_liveness_local.sh",
	// "arguments": "/health/ping_liveness_local.sh 5"
	// but execProbe will have only ["/health/ping_liveness_local.sh", "5"].
	return execProbe[0] == binary && args == JoinArgs(append([]string{binary}, execProbe[1:]...))
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
