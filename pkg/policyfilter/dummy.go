// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// nolint:revive // prevent unused-parameter alert, dummy method obviously don't use args
package policyfilter

import (
	"fmt"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

type dummy struct {
}

func (s *dummy) AddPolicy(polID PolicyID, namespace string, podSelector *slimv1.LabelSelector) error {
	return fmt.Errorf("policyfilter is disabled")
}

func (s *dummy) DelPolicy(polID PolicyID) error {
	return fmt.Errorf("policyfilter is disabled")
}

func (s *dummy) AddPodContainer(podID PodID, namespace string, podLabels labels.Labels, containerID string, cgIDp CgroupID) error {
	return nil
}

func (s *dummy) UpdatePod(podID PodID, namespace string, podLabels labels.Labels, containerIDs []string) error {
	return nil
}

func (s *dummy) DelPodContainer(podID PodID, containerID string) error {
	return nil
}

func (s *dummy) DelPod(podID PodID) error {
	return nil
}

func (s *dummy) RegisterPodHandlers(podInformer cache.SharedIndexInformer) {
}

func (s *dummy) Close() error {
	return nil
}
