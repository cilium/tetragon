// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

const rodataConfigPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "shared-rodata-config"
spec:
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
    - index: 5
`

func unloadRodataSensors(sens []*sensors.Sensor) {
	sensorIfaces := make([]sensors.SensorIface, 0, len(sens))
	for _, sensor := range sens {
		sensorIfaces = append(sensorIfaces, sensor)
	}
	sensors.UnloadSensors(sensorIfaces)
}

func TestObserverSharedRodataConfig(t *testing.T) {
	if !kernels.MinKernelVersion("5.11") {
		t.Skip("shared rodata config requires v5.11 BPF objects")
	}

	oldPerfRB := option.Config.UsePerfRingBuffer
	oldParents := option.Config.ParentsMapEnabled
	oldEnvs := option.Config.EnableProcessEnvironmentVariables
	option.Config.UsePerfRingBuffer = false
	option.Config.ParentsMapEnabled = true
	option.Config.EnableProcessEnvironmentVariables = true
	t.Cleanup(func() {
		option.Config.UsePerfRingBuffer = oldPerfRB
		option.Config.ParentsMapEnabled = oldParents
		option.Config.EnableProcessEnvironmentVariables = oldEnvs
	})

	var iterNum byte
	if bpf.HasKfunc("bpf_iter_num_new") && kernels.MinKernelVersion("6.9") {
		iterNum = 1
	}

	createCrdFile(t, rodataConfigPolicy)
	sens, err := observertesthelper.GetDefaultSensorsWithFile(
		t,
		testConfigFile,
		tus.Conf().TetragonLib,
		observertesthelper.WithKeepCollection(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { unloadRodataSensors(sens) })

	mapIDs := make(map[ebpf.MapID]struct{})
	for _, sensor := range sens {
		for _, load := range sensor.Progs {
			if load.LC == nil {
				continue
			}
			if loadedMap, ok := load.LC.Maps[".rodata.config"]; ok {
				mapIDs[loadedMap.ID] = struct{}{}
			}
		}
	}

	require.Len(t, mapIDs, 1, "all programs should use one shared rodata config map")
	for id := range mapIDs {
		m, err := ebpf.NewMapFromID(id)
		require.NoError(t, err)
		t.Cleanup(func() { m.Close() })

		info, err := m.Info()
		require.NoError(t, err)
		assert.True(t, info.Frozen())

		contents, err := m.LookupBytes(uint32(0))
		require.NoError(t, err)
		require.Len(t, contents, 8)
		assert.Equal(t, iterNum, contents[0], "iter-num flag")
		assert.Equal(t, byte(0), contents[1], "perf-rb flag")
		assert.Equal(t, byte(1), contents[2], "parents-map flag")
		assert.Equal(t, byte(1), contents[3], "environment-variable flag")
	}
}
