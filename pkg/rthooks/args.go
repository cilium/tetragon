// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/watcher"

	corev1 "k8s.io/api/core/v1"
)

const (
	uidStringLen = len("00000000-0000-0000-0000-000000000000")
)

type CreateContainerArg struct {
	Req     *v1.CreateContainer
	Watcher watcher.PodAccessor

	// cached values
	cgroupID       *uint64
	pod            *corev1.Pod
	hostCgroupPath string
}

func (arg *CreateContainerArg) HostCgroupPath() (string, error) {
	if arg.hostCgroupPath == "" {
		cgPath := arg.Req.CgroupsPath
		cgRoot, err := cgroups.HostCgroupRoot()
		if err != nil {
			return "", err
		}
		arg.hostCgroupPath = filepath.Join(cgRoot, cgPath)
	}
	return arg.hostCgroupPath, nil
}

func (arg *CreateContainerArg) CgroupID() (uint64, error) {
	if p := arg.cgroupID; p != nil {
		return *p, nil
	}

	// retrieve the cgroup id from the host cgroup path.
	//
	// NB(kkourt): A better solution might be to hook into cgroup creation routines and create a
	// mapping between directory and cgroup id that we maintain in user-space. Then, we can find
	// the id using this mapping.
	path, err := arg.HostCgroupPath()
	if err != nil {
		return 0, err
	}
	cgID, err := cgroups.GetCgroupIDFromSubCgroup(path)
	if err != nil {
		return 0, err
	}

	arg.cgroupID = &cgID
	return cgID, nil
}

func podIDFromCgroupPath(p string) string {
	podPath := filepath.Dir(p)
	podIDstr := filepath.Base(podPath)
	podIDstr = strings.TrimSuffix(podIDstr, ".slice")
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
	containerID = strings.TrimSuffix(containerID, ".scope")
	return containerID
}

func (arg *CreateContainerArg) ContainerID() (string, error) {
	if arg.Req.ContainerID != "" {
		return arg.Req.ContainerID, nil
	}
	return containerIDFromCgroupPath(arg.Req.CgroupsPath), nil
}

func (arg *CreateContainerArg) Pod() (*corev1.Pod, error) {
	if arg.pod != nil {
		return arg.pod, nil
	}

	var pod *corev1.Pod
	var err error
	if h, ok := arg.Req.Annotations["kubernetes.io/config.hash"]; ok {
		// NB: this is a static pod, so we need to find its mirror in the API server
		pod, err = arg.findMirrorPod(h)
	} else {
		pod, err = arg.findPod()
	}

	if err == nil {
		arg.pod = pod
	}

	return pod, err
}

func (arg *CreateContainerArg) findMirrorPod(hash string) (*corev1.Pod, error) {
	return retry(5, 10*time.Millisecond, func() (*corev1.Pod, error) {
		return arg.Watcher.FindMirrorPod(hash)
	})

}

func (arg *CreateContainerArg) findPod() (*corev1.Pod, error) {
	var err error
	podID, err := arg.PodID()
	if err != nil {
		return nil, err
	}

	return retry(5, 10*time.Millisecond, func() (*corev1.Pod, error) {
		return arg.Watcher.FindPod(podID)
	})
}

func retry[R any](nretries int, timeout time.Duration, fn func() (R, error)) (R, error) {
	var err error
	var ret R
	for i := 0; ; i++ {
		ret, err = fn()
		if err == nil {
			return ret, nil
		}

		if i >= nretries {
			return ret, fmt.Errorf("failed to fetch pod info after %d retries: %w", nretries, err)
		}

		time.Sleep(timeout)
	}
}
