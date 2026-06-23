// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func agentPod(name, node, ip string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	phase := corev1.PodPending
	if ready {
		status = corev1.ConditionTrue
		phase = corev1.PodRunning
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
			Labels:    map[string]string{"app.kubernetes.io/name": "tetragon"},
		},
		Spec: corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			Phase:      phase,
			PodIP:      ip,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

func TestDiscoverAgent_PicksReady(t *testing.T) {
	client := fake.NewSimpleClientset(
		agentPod("tetragon-a", "node-a", "10.0.0.1", false),
		agentPod("tetragon-b", "node-b", "10.0.0.2", true),
	)

	agent, err := DiscoverAgent(context.Background(), client, "kube-system", DefaultAgentLabelSelector, "")
	require.NoError(t, err)
	assert.Equal(t, "node-b", agent.Node)
	assert.Equal(t, "tetragon-b", agent.PodName)
	assert.Equal(t, "10.0.0.2", agent.PodIP)
}

func TestDiscoverAgent_NodeOverride(t *testing.T) {
	client := fake.NewSimpleClientset(
		agentPod("tetragon-a", "node-a", "10.0.0.1", true),
		agentPod("tetragon-b", "node-b", "10.0.0.2", true),
	)

	agent, err := DiscoverAgent(context.Background(), client, "kube-system", DefaultAgentLabelSelector, "node-a")
	require.NoError(t, err)
	assert.Equal(t, "node-a", agent.Node)
}

func TestDiscoverAgent_NoReadyAgent(t *testing.T) {
	client := fake.NewSimpleClientset(
		agentPod("tetragon-a", "node-a", "10.0.0.1", false),
	)

	_, err := DiscoverAgent(context.Background(), client, "kube-system", DefaultAgentLabelSelector, "")
	require.Error(t, err)
}

func TestDiscoverAgent_NodeOverrideNotFound(t *testing.T) {
	client := fake.NewSimpleClientset(
		agentPod("tetragon-a", "node-a", "10.0.0.1", true),
	)

	_, err := DiscoverAgent(context.Background(), client, "kube-system", DefaultAgentLabelSelector, "node-z")
	require.Error(t, err)
}
