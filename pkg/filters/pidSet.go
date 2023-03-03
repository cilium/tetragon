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

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

/* pidSet is the set of pids we are interested in receiving events
 * for. This includes the pids listed in filter and any of their
 * children.
 */
var pidSet map[uint32]bool

func filterByPidSet(pids []uint32) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		for _, pid := range pids {
			if pid == process.Pid.GetValue() {
				pidSet[pid] = true
				return true
			}
		}
		parent := GetParent(ev)
		if parent == nil {
			return false
		}
		if pidSet[parent.Pid.GetValue()] == true {
			return true
		}
		for _, pid := range pids {
			if pid == parent.Pid.GetValue() {
				pidSet[pid] = true
				return true
			}
		}
		return false
	}
}

type PidSetFilter struct{}

func (f *PidSetFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	pidSet = make(map[uint32]bool)
	var fs []hubbleFilters.FilterFunc
	if ff.PidSet != nil {
		fs = append(fs, filterByPidSet(ff.PidSet))
	}
	return fs, nil
}
