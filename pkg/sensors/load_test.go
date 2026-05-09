// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/sensors/program"
)

func TestValidateProgramPinPaths(t *testing.T) {
	sensor := &Sensor{
		Name:   "sensor",
		Policy: "policy",
		Progs: []*program.Program{
			program.Builder("first.o", "", "first", "same-pin", "generic_kprobe"),
			program.Builder("second.o", "", "second", "same-pin", "generic_kprobe"),
		},
	}

	err := sensor.validateProgramPinPaths()
	require.ErrorContains(t, err, "duplicate BPF program pin path")
	require.ErrorContains(t, err, "first")
	require.ErrorContains(t, err, "second")
}

func TestValidateProgramPinPathsAllowsDistinctPins(t *testing.T) {
	sensor := &Sensor{
		Name:   "sensor",
		Policy: "policy",
		Progs: []*program.Program{
			program.Builder("first.o", "", "first", "first-pin", "generic_kprobe"),
			program.Builder("second.o", "", "second", "second-pin", "generic_kprobe"),
		},
	}

	require.NoError(t, sensor.validateProgramPinPaths())
}
