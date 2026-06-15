// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func podPhaseReactor(phase corev1.PodPhase) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		name := action.(k8stesting.GetAction).GetName()
		return true, &corev1.Pod{
			Status: corev1.PodStatus{Phase: phase},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: action.GetNamespace(),
			},
		}, nil
	}
}

func deleteActionSeen(actions []k8stesting.Action) bool {
	for _, a := range actions {
		if a.Matches("delete", "pods") {
			return true
		}
	}
	return false
}

func TestOrchestrator_Run_HappyPath(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "pods", podPhaseReactor(corev1.PodSucceeded))

	o := NewOrchestrator(client, "pt-ns")
	o.pollInterval = time.Millisecond
	o.podLogs = func(_ context.Context, _, _ string) ([]byte, error) {
		return Encode([]TestResult{
			{Name: "t1", Scenarios: []ScenarioResult{{Name: "s1"}}},
		})
	}

	results, err := o.Run(context.Background(), &TestPodSpec{
		Name: "policytest-abc", Namespace: "pt-ns", RunID: "abc", Tests: []string{"t1"},
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "t1", results[0].Name)
	assert.False(t, results[0].Failed())
	assert.True(t, deleteActionSeen(client.Actions()), "pod must be cleaned up")
}

func TestOrchestrator_Run_PodFailedCleansUp(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "pods", podPhaseReactor(corev1.PodFailed))

	o := NewOrchestrator(client, "pt-ns")
	o.pollInterval = time.Millisecond
	o.podLogs = func(_ context.Context, _, _ string) ([]byte, error) {
		return []byte("panic: boom"), nil // not a valid result payload
	}

	_, err := o.Run(context.Background(), &TestPodSpec{
		Name: "policytest-xyz", Namespace: "pt-ns", RunID: "xyz", Tests: []string{"t1"},
	})
	require.Error(t, err)
	assert.True(t, deleteActionSeen(client.Actions()), "pod must be cleaned up even on failure")
}
