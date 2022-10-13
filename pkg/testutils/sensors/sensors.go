package sensors

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/sensors"
)

func RegisterSensorsAtInit(loaded []*sensors.Sensor) {
	for _, s := range loaded {
		sensors.RegisterSensorAtInit(s)
	}
}

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

// TestSensorManager sensor manager used in tests
type TestSensorManager struct {
	Manager *sensors.Manager
}

// StartTestSensorManager starts a new sensor mananger.
// It will use the test name to create a unqique directory for maps/etc, and
// will also register the necessary cleanup functions using t.Cleanup()
func StartTestSensorManager(ctx context.Context, t *testing.T) *TestSensorManager {
	path := bpf.MapPrefixPath()
	mgr, err := sensors.StartSensorManager(path, path, "")
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	t.Cleanup(func() {
		err := mgr.StopSensorManager(ctx)
		if err != nil {
			t.Logf("stopSensorController failed: %s\n", err)
		}
	})

	return &TestSensorManager{
		Manager: mgr,
	}
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
		t.Cleanup(func() {
			tsm.Manager.DisableSensor(ctx, s.Name)
		})
	}
}
