// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	s, err := New(true)
	if err != nil {
		t.Skipf("failed to inialize policy filter state: %s", err)
	}
	defer s.Close()

	err = s.AddPolicy(PolicyID(1), "ns1", nil, nil)
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(2), "ns2", nil, nil)
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(3), "ns3", nil, nil)
	require.NoError(t, err)

	pod1 := PodID(uuid.New())
	cgidi1 := CgroupID(2001)
	err = s.AddPodContainer(pod1, "ns2", "wl2", "kind2", nil, "cont1", cgidi1, "main1")
	require.NoError(t, err)
	cgidi2 := CgroupID(2002)
	err = s.AddPodContainer(pod1, "ns2", "wl2", "kind2", nil, "cont2", cgidi2, "main2")
	require.NoError(t, err)

	pod2 := PodID(uuid.New())
	cgidi3 := CgroupID(1001)
	err = s.AddPodContainer(pod2, "ns1", "wl1", "kind1", nil, "cont3", cgidi3, "main3")
	require.NoError(t, err)

	cgidi4 := CgroupID(3001)
	pod3 := PodID(uuid.New())
	err = s.AddPodContainer(pod3, "ns3", "wl3", "kind3", nil, "cont4", cgidi4, "main4")
	require.NoError(t, err)
	pod4 := PodID(uuid.New())
	cgidi5 := CgroupID(3002)
	err = s.AddPodContainer(pod4, "ns3", "wl3", "kind3", nil, "cont5", cgidi5, "main5")
	require.NoError(t, err)
	cgidi6 := CgroupID(3003)
	err = s.AddPodContainer(pod4, "ns3", "wl3", "kind3", nil, "cont6", cgidi6, "main6")
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
