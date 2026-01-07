// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bugtool

import (
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

	sumMemlock := func(mapInfos []bpf.ExtendedMapInfo) int {
		sumMemlock := 0
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
