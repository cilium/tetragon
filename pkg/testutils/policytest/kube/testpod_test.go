// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// no TLS configured -> no secret volume/mount
	assert.Empty(t, pod.Spec.Volumes)
	assert.Empty(t, c.VolumeMounts)
}

func TestTestPodSpec_TLS(t *testing.T) {
	spec := &TestPodSpec{
		Name: "p", Namespace: "ns", RunID: "r", AgentAddr: "1.2.3.4:54321",
		Tests:         []string{"t"},
		TLSSecret:     "tetragon-server-certs",
		TLSServerName: "tetragon.local",
	}

	pod := spec.Build()

	// secret mounted read-only as a volume
	require.Len(t, pod.Spec.Volumes, 1)
	assert.Equal(t, "tetragon-server-certs", pod.Spec.Volumes[0].Secret.SecretName)

	c := pod.Spec.Containers[0]
	require.Len(t, c.VolumeMounts, 1)
	assert.True(t, c.VolumeMounts[0].ReadOnly)
	mp := c.VolumeMounts[0].MountPath

	// mTLS client flags reference the mounted cert files + SNI override
	assert.Subset(t, c.Args, []string{
		"--tls-ca-cert-files", mp + "/ca.crt",
		"--tls-cert-file", mp + "/tls.crt",
		"--tls-key-file", mp + "/tls.key",
		"--tls-server-name", "tetragon.local",
	})
}

func TestTestPodSpec_RunLabelMatchesSelector(t *testing.T) {
	// the run label set on the pod must be exactly what is passed as the
	// podSelector, so the policy scopes to this pod.
	spec := &TestPodSpec{Name: "p", Namespace: "ns", RunID: "xyz", Tests: []string{"t"}}
	pod := spec.Build()

	assert.Equal(t, map[string]string{runLabelKey: "xyz"}, pod.Labels)
	assert.Contains(t, pod.Spec.Containers[0].Args, runLabelKey+"=xyz")
}
