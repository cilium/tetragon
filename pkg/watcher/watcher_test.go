// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	fakeTetragon "github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFindServiceByIP(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	watcher := NewK8sWatcher(k8sClient, 60*time.Second)
	svc1 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"1.1.1.1"}},
	}
	svc2 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc2"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"2.2.2.2"}},
	}
	svc3 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc3"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"3.3.3.3", "4.4.4.4"}},
	}
	_, err := k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc1, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc2, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc3, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(watcher.serviceInformer.GetStore().List()) == 3 }, 10*time.Second, 1*time.Second)
	res, err := watcher.FindServiceByIP("1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc1", res[0].Name)
	res, err = watcher.FindServiceByIP("4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc3", res[0].Name)
}

func TestPodInfoByIP(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	tetragonClient := fakeTetragon.NewSimpleClientset()
	watcher := NewK8sWatcherWithTetragonClient(k8sClient, tetragonClient, 0)
	pod1 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "1.1.1.1"}}},
	}
	pod2 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod2"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "2.2.2.2"}}},
	}
	pod3 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod3"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "3.3.3.3"}, {IP: "4.4.4.4"}}},
	}
	_, err := tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod1, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod2, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod3, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Eventually(t, func() bool { return len(watcher.podInfoInformer.GetStore().List()) == 3 }, 10*time.Second, 1*time.Second)
	res, err := watcher.FindPodInfoByIP("1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod1", res[0].Name)
	res, err = watcher.FindPodInfoByIP("4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod3", res[0].Name)
	_, err = watcher.FindPodInfoByIP("5.5.5.5")
	assert.Error(t, err)
}
