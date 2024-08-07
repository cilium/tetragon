// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"path/filepath"
	"strings"

	v1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/watcher"
)

const (
	uidStringLen = len("00000000-0000-0000-0000-000000000000")
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

func podIDFromCgroupPath(p string) string {
	podPath := filepath.Dir(p)
	podIDstr := filepath.Base(podPath)
	if len(podIDstr) > uidStringLen {
		// remove pod prefix
		podIDstr = podIDstr[len(podIDstr)-uidStringLen:]
	}
	return podIDstr
}

func (arg *CreateContainerArg) PodID() (string, error) {
	if arg.Req.PodUID != "" {
		return arg.Req.PodUID, nil
	}
	return podIDFromCgroupPath(arg.Req.CgroupsPath), nil
}

func containerIDFromCgroupPath(p string) string {
	containerID := filepath.Base(p)
	// crio has cgroups paths such as crio-<ID> and crio-conmon-<ID>. Strip those prefixes.
	if idx := strings.LastIndex(containerID, "-"); idx != -1 {
		containerID = containerID[idx+1:]
	}
	return containerID
}

func (arg *CreateContainerArg) ContainerID() (string, error) {
	if arg.Req.ContainerID != "" {
		return arg.Req.ContainerID, nil
	}
	return containerIDFromCgroupPath(arg.Req.CgroupsPath), nil
}
