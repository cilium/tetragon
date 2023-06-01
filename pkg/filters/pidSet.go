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
	"github.com/cilium/tetragon/pkg/logger"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

// We could use an LRU here but we really don't want to evict old entries and risk failing
// a test that uses this filter. Instead, we take the safer approach from the perspective
// of testing and opt to grow the map indefinitely and log a warning if the size exceeeds
// a pre-determined threshold. Since we have protections in place to prevent this filter
// being used in production, this should be acceptable.
type ChildCache = map[uint32]struct{}

func checkPidSetMembership(pid uint32, pidSet []uint32, childCache ChildCache) bool {
	// Check the original pidSet. The reason for doing this separately is that we never
	// want to drop the original pidSet from the cache. Keeping this separately in a slice
	// is an easy way to achieve this.
	for _, p := range pidSet {
		if pid == p {
			return true
		}
	}
	// Fall back to childCache to check children.
	_, ok := childCache[pid]
	return ok
}

func doFilterByPidSet(ev *v1.Event, pidSet []uint32, childCache ChildCache, childCacheWarning *int) bool {
	process := GetProcess(ev)
	if process == nil {
		return false
	}

	// Check the process against our cache
	pid := process.Pid.GetValue()
	if checkPidSetMembership(pid, pidSet, childCache) {
		return true
	}

	parent := GetParent(ev)
	if parent == nil {
		return false
	}

	// Check the parent against our cache
	ppid := parent.Pid.GetValue()
	if checkPidSetMembership(ppid, pidSet, childCache) {
		// Add our own PID to the children cache so that we can match our future children.
		childCache[pid] = struct{}{}
		// If we exceeded the pre-determined warning limit, log a warning message and
		// double it.
		if len(childCache) == *childCacheWarning {
			logger.GetLogger().Warnf("pidSet filter cache has exceeded %d entries. To prevent excess memory usage, consider disabling it.", childCacheWarning)
			*childCacheWarning *= 2
		}
		return true
	}

	// No matches, return false
	return false
}

func filterByPidSet(pidSet []uint32, childCache ChildCache, childCacheWarning int) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		return doFilterByPidSet(ev, pidSet, childCache, &childCacheWarning)
	}
}

// PidSetFilter is a filter that matches on a process and all of its children by their
// PID, up to maxChildCacheSize number of children.
type PidSetFilter struct{}

func (f *PidSetFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.PidSet != nil {
		childCache := make(ChildCache)
		childCacheWarning := 8192

		pidSet := ff.PidSet
		fs = append(fs, filterByPidSet(pidSet, childCache, childCacheWarning))
	}
	return fs, nil
}
