// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package policyfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
)

func newPod(contID ...string) *v1.Pod {
	pod := v1.Pod{}
	for _, id := range contID {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, v1.ContainerStatus{
			ContainerID: id,
		})
	}
	return &pod
}

func TestPodContainerDiff(t *testing.T) {
	testCases := []struct {
		oldPod      *v1.Pod
		newPod      *v1.Pod
		expectedAdd []string
		expectedDel []string
	}{
		{
			oldPod:      newPod(),
			newPod:      newPod("c1"),
			expectedAdd: []string{"c1"},
			expectedDel: []string{},
		},
		{
			oldPod:      newPod("c1"),
			newPod:      newPod(),
			expectedAdd: []string{},
			expectedDel: []string{"c1"},
		},
		{
			oldPod:      newPod("c2"),
			newPod:      newPod("c1"),
			expectedAdd: []string{"c1"},
			expectedDel: []string{"c2"},
		},
	}
	for _, tc := range testCases {
		add, del := podContainerDiff(tc.oldPod, tc.newPod)
		require.ElementsMatch(t, tc.expectedAdd, add)
		require.ElementsMatch(t, tc.expectedDel, del)
	}
}
