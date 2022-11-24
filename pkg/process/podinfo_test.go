// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestK8sWatcher_GetPodInfo(t *testing.T) {
	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "kube-system",
			UID:               "1",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			Labels:            map[string]string{"a": "b", "c": "d"},
		},
		Status: v1.PodStatus{
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
	watcher := watcher.NewK8sWatcher(k8sClient, time.Hour)
	pid := uint32(1)
	podInfo, _ := getPodInfo(watcher, "abcd1234", "curl", "cilium.io", 1)
	assert.True(t, proto.Equal(podInfo, &tetragon.Pod{
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
}
