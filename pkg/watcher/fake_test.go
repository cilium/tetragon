// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
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
