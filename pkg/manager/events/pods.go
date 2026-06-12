// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package events exposes the typed pod-event interface that pkg/manager's
// pod informer adapter implements. Consumers (policyfilter, cgidmap, ...)
// depend on this package instead of pkg/manager to avoid pulling in
// controller-runtime as a transitive dependency. The single declaration also
// keeps the pod-lifecycle contract canonical across consumers.
package events

import (
	corev1 "k8s.io/api/core/v1"
)

// PodEventSource delivers typed pod lifecycle callbacks. The concrete adapter
// is in pkg/manager; tests can satisfy this interface with a hand-rolled fake
// (see pkg/policyfilter/k8s_test.go).
type PodEventSource interface {
	OnPodAdd(handler func(pod *corev1.Pod))
	OnPodUpdate(handler func(oldPod, newPod *corev1.Pod))
	OnPodDelete(handler func(pod *corev1.Pod))
}
