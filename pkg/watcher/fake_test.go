// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFakeK8sWatcher_FindServiceByIP(t *testing.T) {
	services := []interface{}{
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
			Spec:       corev1.ServiceSpec{ClusterIPs: []string{"1.1.1.1"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "svc-2"},
			Spec:       corev1.ServiceSpec{ClusterIPs: []string{"2.2.2.2", "3.3.3.3"}},
		},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(nil, services)
	res, err := fakeWatcher.FindServiceByIP("1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0].Name, "svc-1")
	res, err = fakeWatcher.FindServiceByIP("2.2.2.2")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0].Name, "svc-2")
	res, err = fakeWatcher.FindServiceByIP("3.3.3.3")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, res[0].Name, "svc-2")
	_, err = fakeWatcher.FindServiceByIP("4.4.4.4")
	assert.Error(t, err)
}

func TestFakeK8sWatcher_AddService(t *testing.T) {
	services := []interface{}{
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
	services := []interface{}{
		&corev1.Service{},
		&corev1.Service{},
		&corev1.Service{},
	}
	fakeWatcher := NewFakeK8sWatcherWithPodsAndServices(nil, services)
	assert.Len(t, fakeWatcher.services, 3)
	fakeWatcher.ClearAllServices()
	assert.Empty(t, fakeWatcher.services)
}
