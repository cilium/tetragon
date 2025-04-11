// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bugtool

import (
	"os"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

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
		assert.Error(t, err)
		_, err = FindMapsUsedByPinnedProgs(path)
		assert.Error(t, err)
	})

	t.Run("BaseSensorMemlock", func(t *testing.T) {
		tus.LoadInitialSensor(t)

		const path = "/sys/fs/bpf/testSensorBugtool"
		pinnedMaps, err := FindPinnedMaps(path)
		assert.NoError(t, err)
		if assert.NotEmpty(t, pinnedMaps) {
			assert.NotZero(t, pinnedMaps[0].Memlock)
		}

		mapsUsedByProgs, err := FindMapsUsedByPinnedProgs(path)
		assert.NoError(t, err)
		if assert.NotEmpty(t, mapsUsedByProgs) {
			assert.NotZero(t, mapsUsedByProgs[0].Memlock)
		}

		allMaps, err := FindAllMaps()
		assert.NoError(t, err)
		if assert.NotEmpty(t, allMaps) {
			assert.NotZero(t, allMaps[0].Memlock)
		}
	})

}
