// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// fakeInformerSink captures the cache.ResourceEventHandler instances passed by
// the adapter on each AddEventHandler call. Tests can fire events directly
// into the captured handler.
type fakeInformerSink struct {
	handlers []cache.ResourceEventHandler
}

func (f *fakeInformerSink) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	f.handlers = append(f.handlers, handler)
	return nil, nil
}

func (f *fakeInformerSink) latest() cache.ResourceEventHandler {
	if len(f.handlers) == 0 {
		return nil
	}
	return f.handlers[len(f.handlers)-1]
}

func newPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
	}
}

func TestPodEventAdapter_OnPodAdd(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	var got *corev1.Pod
	adapter.OnPodAdd(func(pod *corev1.Pod) {
		got = pod
	})

	pod := newPod("p1")
	require.NotNil(t, sink.latest())
	sink.latest().OnAdd(pod, false)
	require.NotNil(t, got)
	assert.Equal(t, "p1", got.Name)
}

func TestPodEventAdapter_OnPodAdd_IgnoresWrongType(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	called := false
	adapter.OnPodAdd(func(_ *corev1.Pod) {
		called = true
	})

	sink.latest().OnAdd(&corev1.Node{}, false)
	assert.False(t, called, "non-Pod object must not invoke the handler")
}

func TestPodEventAdapter_OnPodUpdate(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	var gotOld, gotNew *corev1.Pod
	adapter.OnPodUpdate(func(oldPod, newPod *corev1.Pod) {
		gotOld, gotNew = oldPod, newPod
	})

	oldPod, newPod := newPod("p1"), newPod("p1")
	newPod.ResourceVersion = "2"
	sink.latest().OnUpdate(oldPod, newPod)

	require.NotNil(t, gotOld)
	require.NotNil(t, gotNew)
	assert.Empty(t, gotOld.ResourceVersion)
	assert.Equal(t, "2", gotNew.ResourceVersion)
}

func TestPodEventAdapter_OnPodDelete_ConcretePod(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	var got *corev1.Pod
	adapter.OnPodDelete(func(pod *corev1.Pod) {
		got = pod
	})

	pod := newPod("doomed")
	sink.latest().OnDelete(pod)
	require.NotNil(t, got)
	assert.Equal(t, "doomed", got.Name)
}

func TestPodEventAdapter_OnPodDelete_DeletedFinalStateUnknown(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	var got *corev1.Pod
	adapter.OnPodDelete(func(pod *corev1.Pod) {
		got = pod
	})

	pod := newPod("doomed-tombstoned")
	tombstone := cache.DeletedFinalStateUnknown{Key: "default/doomed-tombstoned", Obj: pod}
	sink.latest().OnDelete(tombstone)
	require.NotNil(t, got, "DeletedFinalStateUnknown wrapping *corev1.Pod must unwrap")
	assert.Equal(t, "doomed-tombstoned", got.Name)
}

func TestPodEventAdapter_OnPodDelete_IgnoresUnknownShape(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	called := false
	adapter.OnPodDelete(func(_ *corev1.Pod) {
		called = true
	})

	// DFSU wrapping a non-Pod object — handler must NOT fire.
	tombstone := cache.DeletedFinalStateUnknown{Key: "x", Obj: &corev1.Node{}}
	sink.latest().OnDelete(tombstone)

	// Random struct — handler must NOT fire.
	sink.latest().OnDelete(&corev1.Service{})

	assert.False(t, called)
}

func TestPodEventAdapter_RegistersOnePerCall(t *testing.T) {
	sink := &fakeInformerSink{}
	adapter := newPodEventAdapter(sink)

	adapter.OnPodAdd(func(_ *corev1.Pod) {})
	adapter.OnPodUpdate(func(_, _ *corev1.Pod) {})
	adapter.OnPodDelete(func(_ *corev1.Pod) {})

	assert.Len(t, sink.handlers, 3, "each OnPod* call registers one informer handler")
}
