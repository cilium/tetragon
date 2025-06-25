// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func filterByPID(pids []uint32) FilterFunc {
	return func(ev *event.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		for _, pid := range pids {
			if pid == process.Pid.GetValue() {
				return true
			}
		}
		return false
	}
}

type PIDFilter struct{}

func (f *PIDFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.Pid != nil {
		fs = append(fs, filterByPID(ff.Pid))
	}
	return fs, nil
}
