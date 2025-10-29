// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// nolint:revive // prevent unused-parameter alert, disabled method obviously don't use args
package policyfilter

import (
	"errors"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/ebpf"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

func DisabledState() State {
	return &disabled{}
}

type disabled struct {
}

func disabledError() error {
	return errors.New("policyfilter is disabled")
}

func (s *disabled) AddGenericPolicy(polID PolicyID, namespace string, podSelector *slimv1.LabelSelector,
	containerSelector *slimv1.LabelSelector) error {
	return disabledError()
}

func (s *disabled) AddTracingPolicyBinding(polID PolicyID, refPolID PolicyID, namespace string, podLabelSelector *slimv1.LabelSelector,
	containerLabelSelector *slimv1.LabelSelector) error {
	return disabledError()
}

func (s *disabled) DeleteGenericPolicy(polID PolicyID) error {
	if polID == NoFilterPolicyID {
		return nil
	}
	return disabledError()
}

func (s *disabled) DeleteTracingPolicyBinding(polID PolicyID) error {
	return disabledError()
}

func (s *disabled) AddTracingPolicyTemplate(polID PolicyID, cgroupToPolicy *ebpf.Map) error {
	return disabledError()
}

func (s *disabled) DeleteTracingPolicyTemplate(polID PolicyID) error {
	return disabledError()
}

func (s *disabled) AddPodContainer(podID PodID, namespace, workload, kind string, podLabels labels.Labels,
	containerID string, cgID CgroupID, containerInfo podhelpers.ContainerInfo) error {
	return nil
}

func (s *disabled) UpdatePod(podID PodID, namespace, workload, kind string, podLabels labels.Labels,
	containerIDs []string, containerInfo []podhelpers.ContainerInfo) error {
	return nil
}

func (s *disabled) DelPodContainer(podID PodID, containerID string) error {
	return nil
}

func (s *disabled) DelPod(podID PodID) error {
	return nil
}

func (s *disabled) RegisterPodHandlers(podInformer cache.SharedIndexInformer) {
}

func (s *disabled) Close() error {
	return nil
}

func (s *disabled) GetNsId(stateID StateID) (*NSID, bool) {
	return nil, false
}

func (s *disabled) GetIdNs(id NSID) (StateID, bool) {
	return StateID(0), false
}
