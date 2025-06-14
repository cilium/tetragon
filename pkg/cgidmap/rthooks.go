// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgidmap

import (
	"context"

	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/google/uuid"
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

	log := logger.GetLogger().With("rthook", true, "cgidmap", true, "hook", "create-container")

	m, err := GlobalMap()
	if err != nil {
		log.Warn("failed to retrieve cgidmap, not registering rthook", logfields.Error, err)
		return err
	}

	podIDstr, err := arg.PodID()
	if err != nil {
		log.Warn("failed to retrieve pod id, aborting hook", logfields.Error, err)
		return err
	}

	podID, err := uuid.Parse(podIDstr)
	if err != nil {
		log.Warn("failed to parse uuid, aborting hook", "uuid", podIDstr, logfields.Error, err)
		return err
	}

	containerID, err := arg.ContainerID()
	if err != nil {
		log.Warn("failed to retrieve container id, aborting hook", logfields.Error, err)
		return err
	}

	cgID, err := arg.CgroupID()
	if err != nil {
		log.Warn("failed to retrieve cgroup id, aborting hook", logfields.Error, err)
		return err
	}

	if cgPath, err := arg.HostCgroupPath(); err != nil {
		log.Warn("could not retrieve host cgroup path, will not add path to cgroup tracker", logfields.Error, err)
	} else if err := cgtracker.AddCgroupTrackerPath(cgPath); err != nil {
		log.Warn("failed to add path to cgroup tracker", logfields.Error, err)
	}

	m.Add(podID, containerID, cgID)
	return nil
}
