// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgidmap

import (
	"context"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func init() {
	if enabled {
		rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
			CreateContainer: createContainerHook,
		})
	}
}

func createContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	log := logger.GetLogger().WithFields(logrus.Fields{
		"rthook":  true,
		"cgidmap": true,
		"hook":    "create-container",
	})

	m, err := GlobalMap()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve cgidmap, not registering rthook")
		return err
	}

	podIDstr, err := arg.PodID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve pod id, aborting hook")
		return err
	}

	podID, err := uuid.Parse(podIDstr)
	if err != nil {
		log.WithError(err).WithField("uuid", podIDstr).Warn("failed to parse uuid, aborting hook")
		return err
	}

	containerID, err := arg.ContainerID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve container id, aborting hook")
		return err
	}

	cgID, err := arg.CgroupID()
	if err != nil {
		log.WithError(err).Warn("failed to retrieve cgroup id, aborting hook")
		return err
	}

	m.Add(podID, containerID, cgID)
	return nil
}
