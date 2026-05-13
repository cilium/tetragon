// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFakeK8sWatcher_AddService(t *testing.T) {
	services := []any{
		&corev1.Service{},
		&corev1.Service{},
		&corev1.Service{},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(nil, services)
	assert.Len(t, fakeWatcher.services, 3)
	fakeWatcher.AddService(&corev1.Service{})
	assert.Len(t, fakeWatcher.services, 4)
}

func TestFakeK8sWatcher_ClearAllServices(t *testing.T) {
	services := []any{
		&corev1.Service{},
		&corev1.Service{},
		&corev1.Service{},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(nil, services)
	assert.Len(t, fakeWatcher.services, 3)
	fakeWatcher.ClearAllServices()
	assert.Empty(t, fakeWatcher.services)
}

func TestFakeK8sWatcher_DeletePod(t *testing.T) {
	pods := []any{
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3", Namespace: "default"}},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(pods, nil)
	assert.Len(t, fakeWatcher.pods, 3)
	fakeWatcher.RemovePod(pods[1].(*corev1.Pod))
	assert.Len(t, fakeWatcher.pods, 2)
	for _, p := range fakeWatcher.pods {
		pod := p.(*corev1.Pod)
		assert.NotEqual(t, "pod2", pod.Name)
	}
}

func TestFakeK8sWatcher_DeletePodNamespaceMismatch(t *testing.T) {
	pods := []any{
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod3", Namespace: "default"}},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(pods, nil)
	assert.Len(t, fakeWatcher.pods, 3)
	rem := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "other"}}
	fakeWatcher.RemovePod(rem)
	assert.Len(t, fakeWatcher.pods, 3)
}
