// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"github.com/cilium/tetragon/pkg/cgidmap"
)

// resolveContainerID resolves a cgroup tracker ID to a container ID using
// cgidmap. The tracker ID is already resolved in BPF, so no additional
// cgtracker lookup is needed.
func resolveContainerID(cgrpTrackerID uint64) string {
	if cgrpTrackerID == 0 {
		return ""
	}
	m, err := cgidmap.GlobalMap()
	if err != nil {
		return ""
	}
	if containerID, ok := m.Get(cgrpTrackerID); ok {
		return containerID
	}
	return ""
}
