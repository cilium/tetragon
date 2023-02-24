package policyfilter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func requirePfmEqualTo(t *testing.T, m PfMap, val map[uint64][]uint64) {

	checkVals := map[PolicyID]map[CgroupID]struct{}{}
	for k, ids := range val {
		checkVals[PolicyID(k)] = map[CgroupID]struct{}{}
		for _, id := range ids {
			checkVals[PolicyID(k)][CgroupID(id)] = struct{}{}
		}
	}

	mapVals, err := m.readAll()
	require.NoError(t, err)
	require.EqualValues(t, checkVals, mapVals)
}

// TestPfMapOps tests some simple map operations
func TestPfMapOps(t *testing.T) {
	if !bpffsReady {
		t.Skip("failed to initialize bpffs")
	}
	pfm, err := newPfMap()
	require.NoError(t, err)
	defer pfm.release()

	polID1 := PolicyID(100)
	polID2 := PolicyID(200)

	pm1, err := pfm.newPolicyMap(polID1, []CgroupID{10, 20})
	require.NoError(t, err)
	requirePfmEqualTo(t, pfm, map[uint64][]uint64{100: {10, 20}})

	err = pm1.addCgroupIDs([]CgroupID{30})
	require.NoError(t, err)
	requirePfmEqualTo(t, pfm, map[uint64][]uint64{100: {10, 20, 30}})

	err = pm1.delCgroupIDs([]CgroupID{20, 10})
	require.NoError(t, err)
	requirePfmEqualTo(t, pfm, map[uint64][]uint64{100: {30}})

	_, err = pfm.newPolicyMap(polID1, []CgroupID{40, 30})
	require.Error(t, err)

	_, err = pfm.newPolicyMap(polID2, []CgroupID{10, 40, 30})
	require.NoError(t, err)

	requirePfmEqualTo(t, pfm, map[uint64][]uint64{100: {30}, 200: {10, 30, 40}})
}
