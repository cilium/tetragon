// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s && !windows

package policyfilter

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

func TestState(t *testing.T) {
	s, err := New(true)
	if err != nil {
		t.Skipf("failed to inialize policy filter state: %s", err)
	}
	defer s.Close()

	err = s.AddPolicy(PolicyID(1), "ns1", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(2), "ns2", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	err = s.AddPolicy(PolicyID(3), "ns3", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)

	pod1 := PodID(uuid.New())
	cgidi1 := CgroupID(2001)
	err = s.AddPodContainer(pod1, "ns2", nil, "cont1", cgidi1, podhelpers.ContainerInfo{Name: "main1", Repo: "repo1"})
	require.NoError(t, err)
	cgidi2 := CgroupID(2002)
	err = s.AddPodContainer(pod1, "ns2", nil, "cont2", cgidi2, podhelpers.ContainerInfo{Name: "main2", Repo: "repo2"})
	require.NoError(t, err)

	pod2 := PodID(uuid.New())
	cgidi3 := CgroupID(1001)
	err = s.AddPodContainer(pod2, "ns1", nil, "cont3", cgidi3, podhelpers.ContainerInfo{Name: "main3", Repo: "repo3"})
	require.NoError(t, err)

	cgidi4 := CgroupID(3001)
	pod3 := PodID(uuid.New())
	err = s.AddPodContainer(pod3, "ns3", nil, "cont4", cgidi4, podhelpers.ContainerInfo{Name: "main4", Repo: "repo4"})
	require.NoError(t, err)
	pod4 := PodID(uuid.New())
	cgidi5 := CgroupID(3002)
	err = s.AddPodContainer(pod4, "ns3", nil, "cont5", cgidi5, podhelpers.ContainerInfo{Name: "main5", Repo: "repo5"})
	require.NoError(t, err)
	cgidi6 := CgroupID(3003)
	err = s.AddPodContainer(pod4, "ns3", nil, "cont6", cgidi6, podhelpers.ContainerInfo{Name: "main6", Repo: "repo6"})
	require.NoError(t, err)

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {1001},
		2:                       {2001, 2002},
		3:                       {3001, 3002, 3003},
		uint64(AllPodsPolicyID): {1001, 2001, 2002, 3001, 3002, 3003},
	})

	err = s.DelPodContainer(pod2, "cont3")
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {},
		2:                       {2001, 2002},
		3:                       {3001, 3002, 3003},
		uint64(AllPodsPolicyID): {2001, 2002, 3001, 3002, 3003},
	})

	err = s.DelPolicy(PolicyID(1))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {2001, 2002},
		3:                       {3001, 3002, 3003},
		uint64(AllPodsPolicyID): {2001, 2002, 3001, 3002, 3003},
	})

	err = s.DelPolicy(PolicyID(2))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		3:                       {3001, 3002, 3003},
		uint64(AllPodsPolicyID): {2001, 2002, 3001, 3002, 3003},
	})

	err = s.DelPod(pod4)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		3:                       {3001},
		uint64(AllPodsPolicyID): {2001, 2002, 3001},
	})

	err = s.DelPolicy(PolicyID(3))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {2001, 2002, 3001},
	})

	require.Empty(t, s.policies)
	require.Len(t, s.pods, 3)

	err = s.DelPod(pod1)
	require.NoError(t, err)
	err = s.DelPod(pod2)
	require.NoError(t, err)
	err = s.DelPod(pod3)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {},
	})

	require.Empty(t, s.policies)
	require.Empty(t, s.pods)
}

func TestStateAllPodsPolicyEntry(t *testing.T) {
	s, err := New(true)
	if err != nil {
		t.Skipf("failed to inialize policy filter state: %s", err)
	}
	defer s.Close()

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {},
	})

	pod1 := PodID(uuid.New())
	cgid1 := CgroupID(4001)
	err = s.AddPodContainer(pod1, "ns1", nil, "cont1", cgid1, podhelpers.ContainerInfo{Name: "main1", Repo: "repo1"})
	require.NoError(t, err)

	pod2 := PodID(uuid.New())
	cgid2 := CgroupID(4002)
	err = s.AddPodContainer(pod2, "ns2", nil, "cont2", cgid2, podhelpers.ContainerInfo{Name: "main2", Repo: "repo2"})
	require.NoError(t, err)

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	err = s.AddPolicy(PolicyID(1), "ns2", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, nil)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {4002},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	err = s.DelPolicy(PolicyID(1))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	err = s.DelPodContainer(pod1, "cont1")
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {4002},
	})

	err = s.DelPod(pod2)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {},
	})
}

func TestStateAllPodsPolicyEntryWithoutCgroupMap(t *testing.T) {
	s, err := New(false)
	if err != nil {
		t.Skipf("failed to inialize policy filter state: %s", err)
	}
	defer s.Close()

	pod := PodID(uuid.New())
	cgid := CgroupID(5001)
	err = s.AddPodContainer(pod, "ns1", nil, "cont1", cgid, podhelpers.ContainerInfo{Name: "main1", Repo: "repo1"})
	require.NoError(t, err)

	dump, err := s.pfMap.readAll()
	require.NoError(t, err)
	require.Equal(t, map[PolicyID]map[CgroupID]struct{}{
		AllPodsPolicyID: {cgid: {}},
	}, dump.Policy)
	require.Nil(t, dump.Cgroup)

	err = s.DelPodContainer(pod, "cont1")
	require.NoError(t, err)

	dump, err = s.pfMap.readAll()
	require.NoError(t, err)
	require.Equal(t, map[PolicyID]map[CgroupID]struct{}{
		AllPodsPolicyID: {},
	}, dump.Policy)
	require.Nil(t, dump.Cgroup)
}

func TestStateHostSelector(t *testing.T) {
	s, err := New(true)
	if err != nil {
		t.Skipf("failed to inialize policy filter state: %s", err)
	}
	defer s.Close()

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {},
	})

	pod1 := PodID(uuid.New())
	cgid1 := CgroupID(4001)
	err = s.AddPodContainer(pod1, "ns1", nil, "cont1", cgid1, podhelpers.ContainerInfo{Name: "main1", Repo: "repo1"})
	require.NoError(t, err)

	pod2 := PodID(uuid.New())
	cgid2 := CgroupID(4002)
	err = s.AddPodContainer(pod2, "ns2", nil, "cont2", cgid2, podhelpers.ContainerInfo{Name: "main2", Repo: "repo2"})
	require.NoError(t, err)

	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	err = s.AddPolicy(PolicyID(1), "", nil, nil, &slimv1.LabelSelector{})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	// Pod namespace and hostSelector (with NamespacedPolicy)
	// If podSelector or containerSelector is nil no pods will match.
	err = s.AddPolicy(PolicyID(2), "ns1", &slimv1.LabelSelector{}, &slimv1.LabelSelector{}, &slimv1.LabelSelector{})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4001, HostSelectorMode},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	// Pod namespace and hostSelector (with podSelector)
	// If podSelector or containerSelector is nil no pods will match.
	err = s.AddPolicy(PolicyID(3), "", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "k8s:io.kubernetes.pod.namespace",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"ns1"},
		}},
	}, &slimv1.LabelSelector{}, &slimv1.LabelSelector{})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4001, HostSelectorMode},
		3:                       {4001, HostSelectorMode},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	// Pod namespace and hostSelector (with NamespacedPolicy) but with nil podSelector
	// This will not match any pods/containers.
	err = s.AddPolicy(PolicyID(4), "ns1", nil, &slimv1.LabelSelector{}, &slimv1.LabelSelector{})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4001, HostSelectorMode},
		3:                       {4001, HostSelectorMode},
		4:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	// Pod namespace and hostSelector (with podSelector) but with nil containerSelector
	// This will not match any pods/containers.
	err = s.AddPolicy(PolicyID(5), "ns1", &slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{{
			Key:      "k8s:io.kubernetes.pod.namespace",
			Operator: slimv1.LabelSelectorOpIn,
			Values:   []string{"ns1"},
		}},
	}, nil, &slimv1.LabelSelector{})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4001, HostSelectorMode},
		3:                       {4001, HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4001, 4002},
	})

	// Delete cont1 from pod1. cgid1 should be removed.
	err = s.DelPodContainer(pod1, "cont1")
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {HostSelectorMode},
		3:                       {HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4002},
	})

	// Create pod3 with new cgid3. Check that the correct policies applied.
	pod3 := PodID(uuid.New())
	cgid3 := CgroupID(4003)
	err = s.AddPodContainer(pod3, "ns1", nil, "cont1", cgid3, podhelpers.ContainerInfo{Name: "main1", Repo: "repo1"})
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4003, HostSelectorMode},
		3:                       {4003, HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4003, 4002},
	})

	// Delete pod2. cgid2 should be removed.
	err = s.DelPod(pod2)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		1:                       {HostSelectorMode},
		2:                       {4003, HostSelectorMode},
		3:                       {4003, HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4003},
	})

	// Delete policy 1.
	err = s.DelPolicy(PolicyID(1))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {4003, HostSelectorMode},
		3:                       {4003, HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4003},
	})

	// Delete policy 3.
	err = s.DelPolicy(PolicyID(3))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {4003, HostSelectorMode},
		4:                       {HostSelectorMode},
		5:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4003},
	})

	// Delete policy 5.
	err = s.DelPolicy(PolicyID(5))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {4003, HostSelectorMode},
		4:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {4003},
	})

	// Delete policy 4.
	err = s.DelPolicy(PolicyID(4))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {4003, HostSelectorMode},
		uint64(AllPodsPolicyID): {4003},
	})

	// Delete pod3. cgid3 should be removed.
	err = s.DelPod(pod3)
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		2:                       {HostSelectorMode},
		uint64(AllPodsPolicyID): {},
	})

	// Delete policy 2. Nothing left.
	err = s.DelPolicy(PolicyID(2))
	require.NoError(t, err)
	requirePfmEqualTo(t, s.pfMap, map[uint64][]uint64{
		uint64(AllPodsPolicyID): {},
	})
}
