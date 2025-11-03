// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func filterByPid(pids []uint32) FilterFunc {
	return func(ev *event.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		return slices.Contains(pids, process.Pid.GetValue())
	}
}

type PidFilter struct{}

func (f *PidFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.Pid != nil {
		fs = append(fs, filterByPid(ff.Pid))
	}
	return fs, nil
}
