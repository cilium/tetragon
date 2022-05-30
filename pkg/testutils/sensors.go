// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors"
)

// LoadSensor is a helper for loading a sensor in tests
func LoadSensor(ctx context.Context, t *testing.T, sensor *sensors.Sensor) {

	if err := sensor.FindPrograms(ctx); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	mapDir := bpf.MapPrefixPath()
	if err := sensor.Load(ctx, mapDir, mapDir, ""); err != nil {
		t.Fatalf("observerLoadSensor error: %s", err)
	}

	t.Cleanup(func() {
		sensors.UnloadSensor(ctx, mapDir, mapDir, sensor)
	})
}
