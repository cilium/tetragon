// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"sync"
	"testing"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/ebpf"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

var (
	glblState   State
	glblError   error // nolint:errname
	setGlobalPf sync.Once
)

// GetState returns global state for policyfilter
func GetState() (State, error) {
	setGlobalPf.Do(func() {
		if option.Config.EnablePolicyFilter {
			logger.GetLogger().Info("Enabling policy filtering")
			glblState, glblError = New(option.Config.EnablePolicyFilterCgroupMap)
		} else {
			glblState = &disabled{}
			glblError = nil
		}
	})
	return glblState, glblError
}

// ResetStateOnlyForTesting resets the global policyfilter state.
// As the name states, it should only be used for testing.
// We need this because GetState() depends on the
// option.Config.EnablePolicyFilter global and this is only initialized once.
// Callers for this should ensure that no race happens.
func resetStateOnlyForTesting() {
	if glblState != nil {
		glblState.Close()
	}
	if option.Config.EnablePolicyFilter {
		logger.GetLogger().Info("Enabling policy filtering")
		glblState, glblError = New(true)
	} else {
		glblState = &disabled{}
		glblError = nil
	}
}

// TestingEnableAndReset enables policy filter for tests (see ResetStateOnlyForTesting)
func TestingEnableAndReset(t *testing.T) {
	oldEnablePolicyFilterValue := option.Config.EnablePolicyFilter
	option.Config.EnablePolicyFilter = true
	resetStateOnlyForTesting()
	t.Cleanup(func() {
		option.Config.EnablePolicyFilter = oldEnablePolicyFilterValue
		resetStateOnlyForTesting()
	})

}

// State is the policyfilter state interface
// It handles two things:
//   - policies being added and removed
//   - pod containers being added and deleted.
type State interface {
	// AddGenericPolicy adds a policy to the policyfilter state.
	// This means that:
	//  - existing containers of pods that match this policy will be added to the policyfilter map (pfMap)
	//  - from now on, new containers of pods that match this policy will also be added to pfMap
	// pods are matched with:
	//  - namespace for namespaced policies (if namespace == "", then policy is not namespaced)
	//  - label selector
	//  - container field selector
	AddGenericPolicy(polID PolicyID, namespace string, podSelector *slimv1.LabelSelector,
		containerSelector *slimv1.LabelSelector) error

	// DeleteGenericPolicy removes a policy from the state
	DeleteGenericPolicy(polID PolicyID) error

	// AddTracingPolicyBinding adds a policy binding to the policyfilter state.
	AddTracingPolicyBinding(polID PolicyID, refPolID PolicyID, namespace string, podLabelSelector *slimv1.LabelSelector,
		containerLabelSelector *slimv1.LabelSelector) error

	// DeleteTracingPolicyBinding removes a policy binding from the state
	DeleteTracingPolicyBinding(polID PolicyID) error

	// AddTracingPolicyTemplate adds a template for a tracing policy to the state.
	AddTracingPolicyTemplate(polID PolicyID, cgroupToPolicy *ebpf.Map) error

	// DeleteTracingPolicyTemplate removes a template for a tracing policy from the state.
	DeleteTracingPolicyTemplate(polID PolicyID) error

	// AddPodContainer informs policyfilter about a new container and its cgroup id in a pod.
	// The pod might or might not have been encountered before.
	// This method is intended to update policyfilter state from container hooks
	AddPodContainer(podID PodID, namespace, workload, kind string, podLabels labels.Labels,
		containerID string, cgID CgroupID, containerInfo podhelpers.ContainerInfo) error

	// UpdatePod updates the pod state for a pod, where containerIDs contains all the container ids for the given pod.
	// This method is intended to be used from k8s watchers (where no cgroup information is available)
	UpdatePod(podID PodID, namespace, workload, kind string, podLabels labels.Labels,
		containerIDs []string, containerInfo []podhelpers.ContainerInfo) error

	// DelPodContainer informs policyfilter that a container was deleted from a pod
	DelPodContainer(podID PodID, containerID string) error
	// DelPod informs policyfilter that a pod has been deleted
	DelPod(podID PodID) error

	// Report opaque cgroup ID to nsId mapping. This method is intended to allow inspecting
	// and reporting the state of the system to subsystems and tooling.
	GetNsId(stateID StateID) (*NSID, bool)

	GetIdNs(id NSID) (StateID, bool)

	// RegisterPodHandlers can be used to register appropriate pod handlers to a pod informer
	// that for keeping the policy filter state up-to-date.
	RegisterPodHandlers(podInformer cache.SharedIndexInformer)

	// Close releases resources allocated by the Manager. Specifically, we close and unpin the
	// policy filter map.
	Close() error
}
