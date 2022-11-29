// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestK8sWatcher(t *testing.T) {
	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "kube-system",
			UID:               "1",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			Labels:            map[string]string{"a": "b", "c": "d"},
			ManagedFields: []metav1.ManagedFieldsEntry{
				{
					Manager:   "manager",
					Operation: "op",
				},
			},
		},
		Status: v1.PodStatus{
			PodIP: "10.20.0.23",
			ContainerStatuses: []v1.ContainerStatus{
				{
					Image:       "image-name",
					ImageID:     "image-id",
					ContainerID: "containerd://abcd1234",
				},
			},
		},
	}
	_, err := cilium.InitCiliumState(context.Background(), false)
	assert.NoError(t, err)
	k8sClient := fake.NewSimpleClientset(&pod)
	sharedK8sInformerFactory := informers.NewSharedInformerFactory(k8sClient, time.Hour)
	podInformer := sharedK8sInformerFactory.Core().V1().Pods().Informer()
	err = podInformer.SetTransform(podTransformFunc)
	assert.NoError(t, err)
	err = podInformer.AddIndexers(map[string]cache.IndexFunc{
		containerIdx: containerIndexFunc,
		podAddrIdx:   podAddrIndexFunc,
	})
	assert.NoError(t, err)
	sharedK8sInformerFactory.Start(wait.NeverStop)
	sharedK8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	watcher := &K8sWatcher{
		podInformer: podInformer,
	}

	t.Run("get pod info by container ID", func(t *testing.T) {
		pid := uint32(1)
		podInfoByContainerID, _ := watcher.GetPodInfo("abcd1234", "curl", "cilium.io", 1)
		assert.True(t, proto.Equal(podInfoByContainerID, &tetragon.Pod{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Container: &tetragon.Container{
				Id:  pod.Status.ContainerStatuses[0].ContainerID,
				Pid: &wrapperspb.UInt32Value{Value: pid},
				Image: &tetragon.Image{
					Id:   pod.Status.ContainerStatuses[0].ImageID,
					Name: pod.Status.ContainerStatuses[0].Image,
				},
			},
			PodLabels: pod.Labels,
		}))
	})

	t.Run("find pod by addr", func(t *testing.T) {
		podInfoByAddr, _, _ := watcher.FindPod(PodFilter{Addr: pod.Status.PodIP})
		expectedPod := pod.DeepCopy()
		expectedPod.ManagedFields = nil
		assert.Equal(t, expectedPod, podInfoByAddr)
	})
}
