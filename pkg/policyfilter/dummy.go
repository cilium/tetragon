// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package policyfilter

import (
	"fmt"

	"k8s.io/client-go/tools/cache"
)

type dummy struct {
}

func (s *dummy) AddPolicy(polID PolicyID, namespace string) error {
	return fmt.Errorf("AddPolicy has no effect because policyfilter is disabled")
}

func (s *dummy) DelPolicy(polID PolicyID) error {
	return fmt.Errorf("DelPolicy has no effect because policyfilter is disabled")
}

func (s *dummy) AddPodContainer(podID PodID, namespace string, containerID string, cgIDp *CgroupID) error {
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
