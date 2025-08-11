// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"log/slog"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
)

type cgidFinder interface {
	findCgroupID(podID PodID, containerID string) (CgroupID, error)
}

type cgfsFinder struct {
	fsscan.FsScanner
	log *slog.Logger
}

func (s *cgfsFinder) findCgroupID(podID PodID, containerID string) (CgroupID, error) {
	path, err := s.FindContainerPath(types.UID(podID.String()), containerID)
	if errors.Is(err, fsscan.ErrContainerPathWithoutMatchingPodID) {
		s.log.Info("FindCgroupID: found path without matching pod id, continuing.", "pod-id", podID,
			"container-id", containerID)
	} else if err != nil {
		return CgroupID(0), err
	}
	cgid, err := cgroups.GetCgroupIDFromSubCgroup(path)
	return CgroupID(cgid), err
}
