// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestK8sWatcher_GetPodInfo(t *testing.T) {
	controller := true
	pod := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "kube-system",
			UID:               "1",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			Labels:            map[string]string{"a": "b", "c": "d"},
			GenerateName:      "test-workload-",
			OwnerReferences: []metav1.OwnerReference{
				{
					Name:       "test-workload",
					Kind:       "Deployment",
					Controller: &controller,
				},
			},
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

	k8sClient := fake.NewSimpleClientset(&pod)
	k8sWatcher := watcher.NewK8sWatcher(k8sClient, nil, time.Hour)
	err := watcher.AddPodInformer(k8sWatcher, true)
	require.NoError(t, err)
	k8sWatcher.Start()
	pid := uint32(1)
	podInfo := getPodInfo(k8sWatcher, "abcd1234", "curl", "cilium.io", 1)
	assert.True(t, proto.Equal(podInfo, &tetragon.Pod{
		Namespace:    pod.Namespace,
		Workload:     pod.OwnerReferences[0].Name,
		WorkloadKind: pod.OwnerReferences[0].Kind,
		Name:         pod.Name,
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
