// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestSensorLoadPropagatesPostMapLoadHookFailure(t *testing.T) {
	errInitialize := errors.New("policy map initialization failed")
	postLoadCalled := false
	laterInitializerCalled := false
	executable, err := os.Executable()
	require.NoError(t, err)
	policyMap := &program.Map{
		Name:     "already-loaded-policy-map",
		Prog:     &program.Program{Name: executable},
		PinState: program.Idle(),
	}
	// Model a map already owned elsewhere. preLoadMaps adds one sensor
	// reference, which the fatal-load cleanup must release without dropping the
	// original reference.
	policyMap.PinState.RefInc()
	sensor := &Sensor{
		Name: "fatal-post-map-load",
		Maps: []*program.Map{policyMap},
		PostLoadHook: func() error {
			postLoadCalled = true
			return nil
		},
	}
	sensor.AddPostMapLoadHook(func() error { return errInitialize })
	sensor.AddPostMapLoadHook(func() error {
		laterInitializerCalled = true
		return nil
	})

	err = sensor.Load(t.TempDir())

	require.ErrorIs(t, err, errInitialize)
	require.ErrorContains(t, err, "post-map load hook")
	require.False(t, sensor.Loaded)
	require.False(t, laterInitializerCalled, "fatal initializer composition must short-circuit")
	require.False(t, postLoadCalled, "ordinary post-load registration must not run after fatal initialization")
	require.True(t, policyMap.PinState.IsLoaded(), "fatal cleanup must preserve the pre-existing map reference")
	require.NoError(t, policyMap.Unload(false))
	require.False(t, policyMap.PinState.IsLoaded(),
		"fatal cleanup must release the map reference acquired for this sensor")
}

func TestSensorLoadKeepsPostLoadHookBestEffort(t *testing.T) {
	errPostLoad := errors.New("best effort post-load failure")
	sensor := &Sensor{
		Name: "best-effort-post-load",
		PostLoadHook: func() error {
			return errPostLoad
		},
	}

	require.NoError(t, sensor.Load(t.TempDir()))
	require.True(t, sensor.Loaded)
	require.NoError(t, sensor.Unload(false))
}
