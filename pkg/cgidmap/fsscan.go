// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"errors"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/crimetrics"
)

// newCgfsResolver returns a resolver that finds container cgroup paths by scanning
// the cgroup filesystem.
func newCgfsResolver(m Map) *resolver {
	scanner := fsscan.New()
	return newResolver(m, cgfsContainerPath(scanner),
		crimetrics.CgfsResolutionsTotal, crimetrics.CgfsResolutionErrorsTotal)
}

// cgfsContainerPath returns a containerPathFn that resolves a container's cgroup
// path by scanning the cgroup filesystem. The scanner is not safe for concurrent
// use, but the resolver drives it from a single worker goroutine.
func cgfsContainerPath(scanner fsscan.FsScanner) containerPathFn {
	return func(id unmappedID) (string, error) {
		path, err := scanner.FindContainerPath(types.UID(id.podID.String()), id.contID)
		// The container cgroup was found but its parent pod directory did not
		// match. Treat this as a soft hit and use the path, as policyfilter does.
		// Warn because the match is unverified and drives pod association.
		if errors.Is(err, fsscan.ErrContainerPathWithoutMatchingPodID) {
			logger.GetLogger().Warn("cgidmap cgroupfs scan: found path without matching pod id, continuing",
				"pod-id", id.podID, "container-id", id.contID)
			return path, nil
		}
		return path, err
	}
}
