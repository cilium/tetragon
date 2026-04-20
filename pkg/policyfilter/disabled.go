// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

// nolint:revive // prevent unused-parameter alert, disabled method obviously don't use args
package policyfilter

import (
	"errors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

func DisabledState() State {
	return &disabled{}
}

type disabled struct {
}

func (s *disabled) AddPolicy(polID PolicyID, namespace string, podSelector *v1alpha1.LabelSelector,
	containerSelector *v1alpha1.LabelSelector, hostSelector *v1alpha1.LabelSelector) error {
	return errors.New("policyfilter is disabled")
}

func (s *disabled) DelPolicy(polID PolicyID) error {
	if polID == NoFilterPolicyID {
		return nil
	}
	return errors.New("policyfilter is disabled")
}

func (s *disabled) AddPodContainer(podID PodID, namespace string, podLabels labels.Labels,
	containerID string, cgID CgroupID, containerInfo podhelpers.ContainerInfo) error {
	return nil
}

func (s *disabled) UpdatePod(podID PodID, namespace string, podLabels labels.Labels,
	containerIDs []string, containerInfo []podhelpers.ContainerInfo) error {
	return nil
}

func (s *disabled) DelPodContainer(podID PodID, containerID string) error {
	return nil
}

func (s *disabled) DelPod(podID PodID) error {
	return nil
}

func (s *disabled) Close() error {
	return nil
}
