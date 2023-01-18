// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Skip(fmt.Sprintf("failed to inialize policy filter state: %s", err))
	}
	defer s.Close()

	err = s.AddPolicy(PolicyID(1), "ns1")
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(2), "ns2")
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(3), "ns3")
	require.NoError(t, err)

	pod1 := PodID(uuid.New())
	err = s.AddPodContainer(pod1, "ns2", "cont1", 2001)
	require.NoError(t, err)
	err = s.AddPodContainer(pod1, "ns2", "cont2", 2002)
	require.NoError(t, err)

	pod2 := PodID(uuid.New())
	err = s.AddPodContainer(pod2, "ns1", "cont3", 1001)
	require.NoError(t, err)

	pod3 := PodID(uuid.New())
	err = s.AddPodContainer(pod3, "ns3", "cont4", 3001)
	require.NoError(t, err)
	pod4 := PodID(uuid.New())
	err = s.AddPodContainer(pod4, "ns3", "cont5", 3002)
	require.NoError(t, err)
	err = s.AddPodContainer(pod4, "ns3", "cont6", 3003)
	require.NoError(t, err)

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1: {1001},
		2: {2001, 2002},
		3: {3001, 3002, 3003},
	})

	err = s.DelPodContainer(pod2, "cont3")
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1: {},
		2: {2001, 2002},
		3: {3001, 3002, 3003},
	})

	err = s.DelPolicy(PolicyID(1))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2: {2001, 2002},
		3: {3001, 3002, 3003},
	})

	err = s.DelPolicy(PolicyID(2))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		3: {3001, 3002, 3003},
	})

	err = s.DelPod(pod4)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		3: {3001},
	})

	err = s.DelPolicy(PolicyID(3))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{})

	require.Len(t, s.policies, 0)
	require.Len(t, s.pods, 3)

	err = s.DelPod(pod1)
	require.NoError(t, err)
	err = s.DelPod(pod2)
	require.NoError(t, err)
	err = s.DelPod(pod3)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{})

	require.Len(t, s.policies, 0)
	require.Len(t, s.pods, 0)
}
