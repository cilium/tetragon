// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestTestPodSpec_Build(t *testing.T) {
	spec := &TestPodSpec{
		Name:      "policytest-abc",
		Namespace: "pt-ns",
		Node:      "node-b",
		Image:     "tetragon-policytest:latest",
		RunID:     "abc",
		AgentAddr: "10.0.0.2:54321",
		Tests:     []string{"t1"},
	}

	pod := spec.Build()

	// metadata
	assert.Equal(t, "policytest-abc", pod.Name)
	assert.Equal(t, "pt-ns", pod.Namespace)
	assert.Equal(t, "abc", pod.Labels[runLabelKey])

	// scheduling + lifecycle
	assert.Equal(t, "node-b", pod.Spec.NodeName)
	assert.Equal(t, corev1.RestartPolicyNever, pod.Spec.RestartPolicy)

	// container image + args
	require := pod.Spec.Containers
	assert.Len(t, require, 1)
	c := pod.Spec.Containers[0]
	assert.Equal(t, "tetragon-policytest:latest", c.Image)
	// IfNotPresent so a locally-built / kind-loaded image is used instead of
	// being pulled (the default Always would fail for an unpublished :latest).
	assert.Equal(t, corev1.PullIfNotPresent, c.ImagePullPolicy)
	// Privileged so trigger programs that need root capabilities (mount,
	// capabilities, setuid, ...) run as they do locally under sudo.
	if assert.NotNil(t, c.SecurityContext) {
		assert.True(t, *c.SecurityContext.Privileged)
	}
	assert.Equal(t, []string{
		"--server-address", "10.0.0.2:54321",
		"policytest", "run-inpod", "t1",
		"--namespace", "pt-ns",
		"--pod-selector-label", "tetragon.io/policytest-run=abc",
	}, c.Args)
}

func TestTestPodSpec_RunLabelMatchesSelector(t *testing.T) {
	// the run label set on the pod must be exactly what is passed as the
	// podSelector, so the policy scopes to this pod.
	spec := &TestPodSpec{Name: "p", Namespace: "ns", RunID: "xyz", Tests: []string{"t"}}
	pod := spec.Build()

	assert.Equal(t, map[string]string{runLabelKey: "xyz"}, pod.Labels)
	assert.Contains(t, pod.Spec.Containers[0].Args, runLabelKey+"=xyz")
}
