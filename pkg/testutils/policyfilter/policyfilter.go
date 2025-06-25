// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

// DummyPF implements policyfilter.State.
// It's very similar to the disabled state, with the difference that it doesn't
// return an error on AddPolicy and DelPolicy. It can be used in tests where
// a namespaced policy must be loaded, but the policyfilter doesn't matter.
type DummyPF struct{}

func (s *DummyPF) AddPolicy(_ policyfilter.PolicyID, _ string, _ *slimv1.LabelSelector,
	_ *slimv1.LabelSelector) error {
	return nil
}

func (s *DummyPF) DelPolicy(_ policyfilter.PolicyID) error {
	return nil
}

func (s *DummyPF) AddPodContainer(_ policyfilter.PodID, _, _, _ string, _ labels.Labels,
	_ string, _ policyfilter.CgroupID, _ podhelpers.ContainerInfo) error {
	return nil
}

func (s *DummyPF) UpdatePod(_ policyfilter.PodID, _, _, _ string, _ labels.Labels,
	_ []string, _ []podhelpers.ContainerInfo) error {
	return nil
}

func (s *DummyPF) DelPodContainer(_ policyfilter.PodID, _ string) error {
	return nil
}

func (s *DummyPF) DelPod(_ policyfilter.PodID) error {
	return nil
}

func (s *DummyPF) RegisterPodHandlers(_ cache.SharedIndexInformer) {
}

func (s *DummyPF) Close() error {
	return nil
}

func (s *DummyPF) GetNsID(_ policyfilter.StateID) (*policyfilter.NSID, bool) {
	return nil, false
}

func (s *DummyPF) GetIDNs(_ policyfilter.NSID) (policyfilter.StateID, bool) {
	return policyfilter.StateID(0), false
}
