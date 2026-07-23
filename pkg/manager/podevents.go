// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package manager

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/manager/events"
)

// podInformerSink is the subset of cache.SharedIndexInformer the adapter
// requires. Defining it here lets the adapter be unit-tested without spinning
// up a real informer.
type podInformerSink interface {
	AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error)
	GetStore() cache.Store
}

// podEventAdapter implements events.PodEventSource on top of a pod informer.
// Each OnPod* call registers an independent informer handler; client-go
// supports multiple registered handlers on a single informer, and each call
// site only observes the events it asked for. The
// `cache.DeletedFinalStateUnknown` unwrap and the `obj.(*corev1.Pod)` type
// assertion happen once inside the adapter so consumers receive typed
// `*corev1.Pod` directly.
type podEventAdapter struct {
	sink podInformerSink
}

// newPodEventAdapter wraps a pod informer in a typed events.PodEventSource.
func newPodEventAdapter(sink podInformerSink) events.PodEventSource {
	return &podEventAdapter{sink: sink}
}

func (p *podEventAdapter) OnPodAdd(handler func(pod *corev1.Pod)) error {
	if _, err := p.sink.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			handler(pod)
		},
	}); err != nil {
		return fmt.Errorf("failed to register pod Add handler: %w", err)
	}
	return nil
}

func (p *podEventAdapter) OnPodUpdate(handler func(oldPod, newPod *corev1.Pod)) error {
	if _, err := p.sink.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj any) {
			oldPod, ok := oldObj.(*corev1.Pod)
			if !ok {
				return
			}
			newPod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			handler(oldPod, newPod)
		},
	}); err != nil {
		return fmt.Errorf("failed to register pod Update handler: %w", err)
	}
	return nil
}

func (p *podEventAdapter) OnPodDelete(handler func(pod *corev1.Pod)) error {
	if _, err := p.sink.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			pod := unwrapDeletedPod(obj)
			if pod == nil {
				return
			}
			handler(pod)
		},
	}); err != nil {
		return fmt.Errorf("failed to register pod Delete handler: %w", err)
	}
	return nil
}

// ListPods returns the current typed pod snapshot from the shared informer.
func (p *podEventAdapter) ListPods() []*corev1.Pod {
	objects := p.sink.GetStore().List()
	pods := make([]*corev1.Pod, 0, len(objects))
	for _, object := range objects {
		if pod, ok := object.(*corev1.Pod); ok {
			pods = append(pods, pod)
		}
	}
	return pods
}

// unwrapDeletedPod returns the *corev1.Pod from a delete-event object,
// transparently handling the `cache.DeletedFinalStateUnknown` wrapper that
// client-go uses when the watcher missed the actual delete event (e.g., due
// to a lost apiserver connection). Returns nil for any other shape.
func unwrapDeletedPod(obj any) *corev1.Pod {
	switch concrete := obj.(type) {
	case *corev1.Pod:
		return concrete
	case cache.DeletedFinalStateUnknown:
		pod, _ := concrete.Obj.(*corev1.Pod)
		return pod
	default:
		return nil
	}
}
