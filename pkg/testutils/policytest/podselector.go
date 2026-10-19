// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

var errPodSelectorSet = errors.New("policy already has a podSelector")

func injectPodSelector(tp tracingpolicy.TracingPolicy, labels map[string]string) (Policy, error) {
	if tp.TpSpec().PodSelector != nil {
		return "", errPodSelectorSet
	}
	tp.TpSpec().PodSelector = &slimv1.LabelSelector{MatchLabels: labels}
	out, err := yaml.Marshal(tp)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}
	return Policy(out), nil
}
