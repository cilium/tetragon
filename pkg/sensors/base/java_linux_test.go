// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package base

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestRegisterJava(t *testing.T) {
	eventsProgram := program.Builder("events.o", "", "", "events", "")
	eventsMap := program.MapBuilder(RingBufMapName, eventsProgram)
	execveMap := program.MapBuilder(ExecveMap.Name, eventsProgram)
	sensor := &sensors.Sensor{Maps: []*program.Map{eventsMap, execveMap}}

	got, err := registerJava(sensor)
	require.NoError(t, err)
	require.Len(t, got.Progs, 1)
	require.Equal(t, "syscall", got.Progs[0].Type)
	require.Same(t, eventsMap, got.Progs[0].PinMap[RingBufMapName])
	require.Same(t, execveMap, got.Progs[0].PinMap[ExecveMap.Name])
	require.Len(t, got.Maps, 4)
	require.Equal(t, JavaMapName, got.Maps[2].Name)
	require.Equal(t, program.MapTypeGlobal, got.Maps[2].Type)
	entries, ok := got.Maps[2].GetMaxEntries()
	require.True(t, ok)
	require.Equal(t, uint32(JavaMapSize), entries)
	require.Equal(t, program.MapTypeProgram, got.Maps[3].Type)
}
