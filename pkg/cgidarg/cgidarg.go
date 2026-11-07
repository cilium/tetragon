// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgidarg

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/cgroups"
)

// Parse parses a string and returns a cgroup id
func Parse(s string) (uint64, error) {
	if sid := strings.TrimPrefix(s, "id:"); len(sid) < len(s) {
		fmt.Printf("sid:%s s:%s\n", sid, s)
		ret, err := strconv.ParseUint(sid, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse id '%s' from argument '%s': %w", sid, s, err)
		}
		return ret, nil
	}
	if sfname := strings.TrimPrefix(s, "fname:"); len(sfname) < len(s) {
		ret, err := cgroups.GetCgroupIDFromPath(sfname)
		if err != nil {
			return 0, fmt.Errorf("cannot get cgroup id for path %s from argument %s: %w", sfname, s, err)
		}
		return ret, nil
	}
	if id, err := strconv.ParseUint(s, 10, 64); err == nil {
		return id, nil
	}
	return cgroups.GetCgroupIDFromPath(s)
}
