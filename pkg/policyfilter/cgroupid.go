// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type cgidFinder interface {
	findCgroupID(podID PodID, containerID string) (CgroupID, error)
}

type cgfsFinder struct {
	fsscan.FsScanner
	log logrus.FieldLogger
}

func (s *cgfsFinder) findCgroupID(podID PodID, containerID string) (CgroupID, error) {
	path, err := s.FindContainerPath(uuid.UUID(podID), containerID)
	if errors.Is(err, fsscan.ErrContainerPathWithoutMatchingPodID) {
		s.log.WithFields(logrus.Fields{
			"pod-id":       podID,
			"container-id": containerID,
		}).Info("FindCgroupID: found path without matching pod id, continuing.")
	} else if err != nil {
		return CgroupID(0), err
	}
	cgid, err := cgroups.GetCgroupIdFromPath(path)
	return CgroupID(cgid), err
}
