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

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/isovalent/tetragon-oss/api/v1/fgs"
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

func (f *PidFilter) OnBuildFilter(_ context.Context, ff *fgs.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.Pid != nil {
		fs = append(fs, filterByPid(ff.Pid))
	}
	return fs, nil
}
