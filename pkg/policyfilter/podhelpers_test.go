// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package policyfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newPodInfo(contID ...string) podInfo {
	pod := podInfo{}
	for _, id := range contID {
		pod.containers = append(pod.containers, containerInfo{
			id: id,
		})
	}
	return pod
}

func TestPodContainerDiff(t *testing.T) {
	testCases := []struct {
		oldinfo     podInfo
		newids      []string
		expectedAdd []string
		expectedDel []string
	}{
		{
			oldinfo:     newPodInfo(),
			newids:      []string{"c1"},
			expectedAdd: []string{"c1"},
			expectedDel: []string{},
		},
		{
			oldinfo:     newPodInfo("c1"),
			newids:      []string{},
			expectedAdd: []string{},
			expectedDel: []string{"c1"},
		},
		{
			oldinfo:     newPodInfo("c2"),
			newids:      []string{"c1"},
			expectedAdd: []string{"c1"},
			expectedDel: []string{"c2"},
		},
	}
	for _, tc := range testCases {
		add, del := tc.oldinfo.containerDiff(tc.newids)
		require.ElementsMatch(t, tc.expectedAdd, add, "expected add result failed for: %+v", tc)
		require.ElementsMatch(t, tc.expectedDel, del, "expected del result failed for: %+v", tc)
	}
}
