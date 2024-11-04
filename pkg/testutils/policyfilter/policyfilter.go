// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

// DummyPF implements policyfilter.State.
// It's very similar to the disabled state, with the difference that it doesn't
// return an error on AddPolicy and DelPolicy. It can be used in tests where
// a namespaced policy must be loaded, but the policyfilter doesn't matter.
type DummyPF struct{}

func (s *DummyPF) AddPolicy(polID policyfilter.PolicyID, namespace string, podSelector *slimv1.LabelSelector,
	containerSelector *slimv1.LabelSelector) error {
	return nil
}

func (s *DummyPF) DelPolicy(polID policyfilter.PolicyID) error {
	return nil
}

func (s *DummyPF) AddPodContainer(podID policyfilter.PodID, namespace, workload, kind string, podLabels labels.Labels,
	containerID string, cgID policyfilter.CgroupID, containerName string) error {
	return nil
}

func (s *DummyPF) UpdatePod(podID policyfilter.PodID, namespace, workload, kind string, podLabels labels.Labels,
	containerIDs []string, containerNames []string) error {
	return nil
}

func (s *DummyPF) DelPodContainer(podID policyfilter.PodID, containerID string) error {
	return nil
}

func (s *DummyPF) DelPod(podID policyfilter.PodID) error {
	return nil
}

func (s *DummyPF) RegisterPodHandlers(podInformer cache.SharedIndexInformer) {
}

func (s *DummyPF) Close() error {
	return nil
}

func (s *DummyPF) GetNsId(stateID policyfilter.StateID) (*policyfilter.NSID, bool) {
	return nil, false
}

func (s *DummyPF) GetIdNs(id policyfilter.NSID) (policyfilter.StateID, bool) {
	return policyfilter.StateID(0), false
}
