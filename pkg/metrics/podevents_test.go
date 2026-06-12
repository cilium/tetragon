// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s && !windows

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakePodEventSource is a hand-rolled fake satisfying the metrics PodEventSource
// contract. It captures the registered delete handler and exposes a method for
// the test to fire a pod-delete event into the consumer.
type fakePodEventSource struct {
	delete func(pod *corev1.Pod)
}

func (f *fakePodEventSource) OnPodDelete(handler func(pod *corev1.Pod)) {
	f.delete = handler
}

func (f *fakePodEventSource) firePodDelete(pod *corev1.Pod) {
	if f.delete != nil {
		f.delete(pod)
	}
}

func TestRegisterPodDeleteHandler_RegistersDeleteCallback(t *testing.T) {
	source := &fakePodEventSource{}
	RegisterPodDeleteHandler(source)
	require.NotNil(t, source.delete, "RegisterPodDeleteHandler must register OnPodDelete")
}

func TestRegisterPodDeleteHandler_EnqueuesPodOnDelete(t *testing.T) {
	// Drive the delayed queue with no wait so the test does not sleep for
	// the production-default minute. Restore on cleanup.
	prev := deleteDelay
	deleteDelay = 0
	t.Cleanup(func() { deleteDelay = prev })

	source := &fakePodEventSource{}
	RegisterPodDeleteHandler(source)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"},
	}
	source.firePodDelete(pod)

	queue := GetPodQueue()
	t.Cleanup(func() {
		// Drain anything left so the queue does not bleed state into
		// other tests in this package.
		for queue.Len() > 0 {
			item, _ := queue.Get()
			queue.Done(item)
		}
	})

	require.Eventually(t, func() bool {
		return queue.Len() >= 1
	}, 2*time.Second, 10*time.Millisecond, "delete event must enqueue the pod")

	got, _ := queue.Get()
	defer queue.Done(got)
	gotPod, ok := got.(*corev1.Pod)
	require.True(t, ok, "queued item must be *corev1.Pod")
	assert.Equal(t, "p1", gotPod.Name)
	assert.Equal(t, "ns", gotPod.Namespace)
}
