// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils/policytest/kube"
)

func TestRunCmd_KubeFlag(t *testing.T) {
	cmd := runCmd()
	require.NotNil(t, cmd.Flags().Lookup("kube"), "run must have a --kube flag")
	for _, f := range []string{"namespace", "node", "image", "agent-namespace", "tls-secret", "tls-server-name"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), "run must have --"+f)
	}
}

func TestNew_NoRunKubeSubcommand(t *testing.T) {
	for _, c := range New().Commands() {
		assert.NotEqual(t, "run-kube", c.Name(), "run-kube must be replaced by run --kube")
	}
}

func TestKubeOptsPodSpec(t *testing.T) {
	opts := kubeOpts{
		namespace: "pt-ns",
		image:     "tetragon-policytest:latest",
		agentPort: 54321,
	}
	agent := &kube.Agent{Node: "node-b", PodName: "tetragon-b", PodIP: "10.0.0.2"}

	spec := opts.podSpec("abc", agent, []string{"t1", "t2"})

	assert.Equal(t, "policytest-abc", spec.Name)
	assert.Equal(t, "pt-ns", spec.Namespace)
	assert.Equal(t, "node-b", spec.Node)
	assert.Equal(t, "tetragon-policytest:latest", spec.Image)
	assert.Equal(t, "abc", spec.RunID)
	assert.Equal(t, "10.0.0.2:54321", spec.AgentAddr)
	assert.Equal(t, []string{"t1", "t2"}, spec.Tests)
}

func TestValidateTests(t *testing.T) {
	assert.NoError(t, validateTests(nil))
	err := validateTests([]string{"nosuch-test"})
	require.ErrorIs(t, err, errUnknownTests)
	assert.Contains(t, err.Error(), "nosuch-test")
}

func TestAnyFailed(t *testing.T) {
	assert.False(t, anyFailed([]kube.TestResult{
		{Name: "t1", Scenarios: []kube.ScenarioResult{{Name: "s1"}}},
		{Name: "t2", Skipped: "old kernel"},
	}))
	assert.True(t, anyFailed([]kube.TestResult{
		{Name: "t1", Scenarios: []kube.ScenarioResult{{Name: "s1"}}},
		{Name: "t2", Err: "boom"},
	}))
}
