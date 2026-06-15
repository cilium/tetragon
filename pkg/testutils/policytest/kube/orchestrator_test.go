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
	return actionSeen(actions, "delete", "pods")
}

func actionSeen(actions []k8stesting.Action, verb, resource string) bool {
	for _, a := range actions {
		if a.Matches(verb, resource) {
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
		data, _ := Encode([]TestResult{
			{Name: "t1", Scenarios: []ScenarioResult{{Name: "s1"}}},
		})
		return []byte("level=warn msg=\"noise\"\n" + ResultMarker + string(data) + "\n"), nil
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

func TestOrchestrator_Run_CopiesTLSSecret(t *testing.T) {
	srcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tetragon-server-certs", Namespace: "tetragon"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"ca.crt": []byte("ca"), "tls.crt": []byte("c"), "tls.key": []byte("k")},
	}
	client := fake.NewSimpleClientset(srcSecret)
	client.PrependReactor("get", "pods", podPhaseReactor(corev1.PodSucceeded))

	o := NewOrchestrator(client, "pt-ns")
	o.TLSSecretSourceNamespace = "tetragon"
	o.pollInterval = time.Millisecond
	o.podLogs = func(_ context.Context, _, _ string) ([]byte, error) {
		data, _ := Encode([]TestResult{{Name: "t1"}})
		return []byte(ResultMarker + string(data) + "\n"), nil
	}

	_, err := o.Run(context.Background(), &TestPodSpec{
		Name: "p", Namespace: "pt-ns", RunID: "r", Tests: []string{"t1"},
		TLSSecret: "tetragon-server-certs",
	})
	require.NoError(t, err)

	// secret was copied into the test namespace and cleaned up
	assert.True(t, actionSeen(client.Actions(), "create", "secrets"), "TLS secret must be copied in")
	assert.True(t, actionSeen(client.Actions(), "delete", "secrets"), "copied TLS secret must be cleaned up")
}

func TestOrchestrator_Run_CleansUpAfterTimeout(t *testing.T) {
	client := fake.NewSimpleClientset()
	// Pod never completes, so waitForCompletion blocks until the context times out.
	client.PrependReactor("get", "pods", podPhaseReactor(corev1.PodPending))

	o := NewOrchestrator(client, "pt-ns")
	o.pollInterval = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := o.Run(ctx, &TestPodSpec{
		Name: "p", Namespace: "pt-ns", RunID: "r", Tests: []string{"t"},
	})
	require.Error(t, err)
	// The deferred cleanup must use a fresh context, so the pod is deleted even
	// though the run context is already cancelled.
	assert.True(t, deleteActionSeen(client.Actions()), "pod must be cleaned up after a ctx timeout")
}

func TestOrchestrator_CopyTLSSecret_Idempotent(t *testing.T) {
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tetragon-server-certs", Namespace: "tetragon"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.key": []byte("real-key")},
	}
	// A copy stranded by a previous interrupted run.
	stale := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tetragon-server-certs", Namespace: "pt-ns"},
		Data:       map[string][]byte{"tls.key": []byte("stale")},
	}
	client := fake.NewSimpleClientset(src, stale)

	o := NewOrchestrator(client, "pt-ns")
	o.TLSSecretSourceNamespace = "tetragon"

	cleanup, err := o.copyTLSSecret(context.Background(), "tetragon-server-certs")
	require.NoError(t, err, "copy must succeed despite a pre-existing stale copy")
	defer cleanup()

	got, err := client.CoreV1().Secrets("pt-ns").Get(context.Background(), "tetragon-server-certs", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, []byte("real-key"), got.Data["tls.key"], "stale copy must be replaced by the source")
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
