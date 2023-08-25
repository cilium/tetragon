// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

func filterByPid(pids []uint32) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
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

type PidFilter struct{}

func (f *PidFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.Pid != nil {
		fs = append(fs, filterByPid(ff.Pid))
	}
	return fs, nil
}
