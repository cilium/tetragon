// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package policyfilter

import (
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"k8s.io/client-go/tools/cache"
)

var (
	glblState   State
	glblError   error
	setGlobalPf sync.Once
)

// GetState returns global state for policyfilter
func GetState() (State, error) {
	setGlobalPf.Do(func() {
		if option.Config.EnablePolicyFilter {
			logger.GetLogger().Info("Enabling policy filtering")
			glblState, glblError = New()
		} else {
			glblState = &dummy{}
			glblError = nil
		}
	})
	return glblState, glblError
}

// State is the policyfilter state interface
// It handles two things:
//   - policies being added and removed
//   - pod continers being created and deleted.
type State interface {
	// AddPolicy adds state a policy to the state
	AddPolicy(polID PolicyID, namespace string) error
	// DelPolicy will removes a policy from the state
	DelPolicy(polID PolicyID) error

	// AddPodContainer informs policyfilter about a new container in a pod.
	// if the cgroup id of the container is known, cgID is not nil and it contains its value.
	//
	// The pod might or might not have been encountered before.
	AddPodContainer(podID PodID, namespace string, containerID string, cgIDp *CgroupID) error
	// DelPodContainer informs policyfilter that a container was deleted from a pod
	DelPodContainer(podID PodID, containerID string) error
	// DelPod informs policyfilter that a pod has been deleted
	DelPod(podID PodID) error

	// RegisterPodHandlers can be used to register appropriate pod handlers to a pod informer
	// that for keeping the policy filter state up-to-date.
	RegisterPodHandlers(podInformer cache.SharedIndexInformer)

	// Close releases resources allocated by the Manager. Specifically, we close and unpin the
	// policy filter map.
	Close() error
}
