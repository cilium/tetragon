// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package watcher

import (
	"errors"
)

var nonK8sErr = errors.New("non k8s build")

// PodAccessor defines an interface for accessing pods from Kubernetes API.
type PodAccessor interface {
	// Find a pod/container pair for the given container ID.
	FindContainer(containerID string) (any, any, bool)
	// Find a pod given the podID
	FindPod(podID string) (any, error)
	// Find a mirror pod for a static pod
	FindMirrorPod(hash string) (any, error)
}

// PodAccessorImpl for non-k8s builds
type nok8sImpl struct{}

func (watcher *nok8sImpl) FindContainer(podID string) (any, any, bool) {
	return nil, nil, false
}

func (watcher *nok8sImpl) FindPod(podID string) (any, error) {
	return nil, nonK8sErr
}

func (watcher *nok8sImpl) FindMirrorPod(hash string) (any, error) {
	return nil, nonK8sErr
}

func NewFakeK8sWatcher(pods []interface{}) *nok8sImpl {
	return &nok8sImpl{}
}
