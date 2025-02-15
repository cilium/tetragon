// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
)

// LoadSensor is a helper for loading a sensor in tests
func LoadSensor(t *testing.T, sensori sensors.SensorIface) {
	sensor, ok := sensori.(*sensors.Sensor)
	if !ok {
		t.Fatalf("Cannot call LoadSensor on type %T", sensori)
	}

	if err := sensor.FindPrograms(); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	bpfDir := bpf.MapPrefixPath()
	if err := sensor.Load(bpfDir); err != nil {
		t.Fatalf("observerLoadSensor error: %s", err)
	}

	t.Cleanup(func() {
		sensor.Unload(true)
	})
}

func LoadInitialSensor(t *testing.T) {
	LoadSensor(t, base.GetInitialSensorTest(t))

	if err := procevents.GetRunningProcs(); err != nil {
		t.Fatalf("procevents.GetRunningProcs: %s", err)
	}
}

// TestSensorManager sensor manager used in tests
type TestSensorManager struct {
	Manager *sensors.Manager
}

// AddAndEnableSensor is a helper function that adds and enables a new sensor
func (tsm *TestSensorManager) AddAndEnableSensor(
	ctx context.Context,
	t *testing.T,
	sensor *sensors.Sensor,
	sensorName string,
) {
	if err := tsm.Manager.AddSensor(ctx, sensorName, sensor); err != nil {
		t.Fatalf("failed to add generic tracepoint sensor: %s", err)
	}
	t.Cleanup(func() {
		tsm.Manager.RemoveSensor(ctx, sensorName)
	})
	if err := tsm.Manager.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}
	t.Cleanup(func() {
		tsm.Manager.DisableSensor(ctx, sensorName)
	})
}

// EnableSensors is a helper function that enables a list of sensors
func (tsm *TestSensorManager) EnableSensors(
	ctx context.Context,
	t *testing.T,
	targets []*sensors.Sensor,
) {
	for _, s := range targets {
		if err := tsm.Manager.EnableSensor(ctx, s.Name); err != nil {
			t.Fatalf("EnableSensor error: %s", err)
		}
	}
}

// AddAndEnableSensor is a helper function that adds and enables a new sensor
func (tsm *TestSensorManager) AddAndEnableSensors(
	ctx context.Context,
	t *testing.T,
	targets []*sensors.Sensor,
) {
	for i := range targets {
		sensor := targets[i]
		tsm.AddAndEnableSensor(ctx, t, sensor, sensor.Name)
	}
}

// EnableSensors is a helper function that enables a list of sensors
func (tsm *TestSensorManager) DisableSensors(
	ctx context.Context,
	t *testing.T,
	targets []*sensors.Sensor,
) {
	for _, s := range targets {
		err := tsm.Manager.DisableSensor(ctx, s.Name)
		if err != nil {
			t.Logf("DisableSensor failed: %s", err)
		}
	}
}
