// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package policyfilter

import (
	"errors"
	"fmt"
	"sync"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

type State struct{}

var (
	glblState   State
	glblError   error // nolint:errname
	setGlobalPf sync.Once
)

// GetState returns global state for policyfilter
func GetState() (State, error) {
	setGlobalPf.Do(func() {
		if option.Config.EnablePolicyFilter {
			glblError = fmt.Errorf("policyfilter is not suported in non-k8s build")
		} else {
			glblState = State{}
			glblError = nil
		}
	})
	return glblState, glblError
}

// see k8s.go
func resetStateOnlyForTesting() {
	glblState = State{}
	glblError = nil
}

func (s *State) DelPolicy(polID PolicyID) error {
	if polID == NoFilterPolicyID {
		return nil
	}
	return errors.New("policyfilter is disabled")
}

func (s *State) AddPodContainer(podID PodID, namespace, workload, kind string, podLabels labels.Labels,
	containerID string, cgID CgroupID, containerInfo podhelpers.ContainerInfo) error {
	return nil
}

func (s *State) AddPolicy(polID PolicyID, namespace string, podSelector *slimv1.LabelSelector,
	containerSelector *slimv1.LabelSelector, hostSelector *slimv1.LabelSelector) error {
	return nil
}

// for matchWorkloads
func GetSelectorPolicyID() PolicyID {
	return PolicyID(0)
}
