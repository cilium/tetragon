// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgidmap

import (
	"context"

	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func init() {
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: createContainerHook,
	})
}

func createContainerHook(_ context.Context, arg *rthooks.CreateContainerArg) error {
	if !option.Config.EnableCgIDmap {
		return nil
	}

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

	if cgPath, err := arg.HostCgroupPath(); err != nil {
		log.WithError(err).Warn("could not retrieve host cgroup path, will not add path to cgroup tracker")
	} else if err := cgtracker.AddCgroupTrackerPath(cgPath); err != nil {
		log.WithError(err).Warn("failed to add path to cgroup tracker")
	}

	m.Add(podID, containerID, cgID)
	return nil
}
