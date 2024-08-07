// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"path/filepath"

	v1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/watcher"
)

type CreateContainerArg struct {
	Req     *v1.CreateContainer
	Watcher watcher.K8sResourceWatcher
}

func (arg *CreateContainerArg) CgroupID() (uint64, error) {

	// retrieve the cgroup id from the host cgroup path.
	//
	// NB(kkourt): A better solution might be to hook into cgroup creation routines and create a
	// mapping between directory and cgroup id that we maintain in user-space. Then, we can find
	// the id using this mapping.
	cgPath := arg.Req.CgroupsPath
	cgRoot, err := cgroups.HostCgroupRoot()
	if err != nil {
		return 0, err
	}

	path := filepath.Join(cgRoot, cgPath)
	cgID, err := cgroups.GetCgroupIdFromPath(path)
	if err != nil {
		return 0, err
	}

	return cgID, nil
}
