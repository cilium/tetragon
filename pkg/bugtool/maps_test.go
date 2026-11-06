// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bugtool

import (
	"encoding/json/v2"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	// needed to register the probe type execve for the base sensor
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorBugtool")
	os.Exit(ec)
}

func TestFindMaps(t *testing.T) {
	t.Run("NoSuchFile", func(t *testing.T) {
		const path = "/sys/fs/bpf/nosuchfile"
		_, err := FindPinnedMaps(path)
		require.Error(t, err)
		_, err = FindMapsUsedByPinnedProgs(path)
		require.Error(t, err)
	})

	sumMemlock := func(mapInfos []bpf.ExtendedMapInfo) uint64 {
		sumMemlock := uint64(0)
		for _, mapInfo := range mapInfos {
			sumMemlock += mapInfo.Memlock
		}
		return sumMemlock
	}

	t.Run("BaseSensorMemlock", func(t *testing.T) {
		tus.LoadInitialSensor(t)

		const path = "/sys/fs/bpf/testSensorBugtool"
		pinnedMaps, err := FindPinnedMaps(path)
		require.NoError(t, err)
		if assert.NotEmpty(t, pinnedMaps) {
			assert.NotZero(t, sumMemlock(pinnedMaps))
		}

		mapsUsedByProgs, err := FindMapsUsedByPinnedProgs(path)
		require.NoError(t, err)
		if assert.NotEmpty(t, mapsUsedByProgs) {
			assert.NotZero(t, sumMemlock(mapsUsedByProgs))
		}

		allMaps, err := FindAllMaps()
		require.NoError(t, err)
		if assert.NotEmpty(t, allMaps) {
			assert.NotZero(t, sumMemlock(allMaps))
		}
	})

}

func TestMapsChecksOutputJSON(t *testing.T) {
	// zero numbers are omitted, as the json output of "tetra debug maps" always did
	out := MapsChecksOutput{
		DiffMaps:       []DiffMap{{ID: 7, Name: "m", Type: "Hash", KeySize: 4}},
		AggregatedMaps: []AggregatedMap{{Name: "a", Count: 2, PercentOfTotal: 50.5}},
	}
	out.MapsStats.Diff = 1

	b, err := json.Marshal(&out)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"total_memlock_bytes": {},
		"maps_stats": {"diff": 1},
		"diff_maps": [{"id": 7, "name": "m", "type": "Hash", "key_size": 4}],
		"aggregated_maps": [{"name": "a", "count": 2, "percent_of_total": 50.5}]
	}`, string(b))

	b, err = json.Marshal(&MapsChecksOutput{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"total_memlock_bytes": {}, "maps_stats": {}}`, string(b))
}
