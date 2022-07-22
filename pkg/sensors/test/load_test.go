package test

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
)

const (
	testConfigFile = "/tmp/tetragon.gotest.yaml"
	loaderBpfDir   = "/sys/fs/bpf/testSensorTest/"
	loaderMapDir   = loaderBpfDir
)

func setupConfig() {
	option.Config.HubbleLib = os.Getenv("TETRAGON_LIB")
	if option.Config.HubbleLib == "" {
		option.Config.HubbleLib = tus.Conf().TetragonLib
	}
	procfs := os.Getenv("TETRAGON_PROCFS")
	if procfs != "" {
		option.Config.ProcFS = procfs
	}

	option.Config.MapDir = tus.Conf().TetragonLib
	option.Config.BpfDir = tus.Conf().TetragonLib
	option.Config.Verbosity = 5
}

func TestLoadInitialSensor(t *testing.T) {
	setupConfig()

	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "event_execve", Type: ebpf.TracePoint},
		1: tus.SensorProg{Name: "event_exit", Type: ebpf.TracePoint},
		2: tus.SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2}},
		tus.SensorMap{Name: "execve_map_stats", Progs: []uint{0, 1, 2}},
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2}},
		tus.SensorMap{Name: "names_map", Progs: []uint{0}},
		tus.SensorMap{Name: "execve_val", Progs: []uint{2}},
	}

	sensor := base.GetInitialSensor()

	t.Logf("Loading sensor %v\n", sensor.Name)
	if err := sensor.Load(context.TODO(), loaderBpfDir, loaderBpfDir, ""); err != nil {
		t.Fatalf("sensor.Load failed: %v\n", err)
	}

	var colls []*ebpf.Collection

	for _, load := range sensor.Progs {
		colls = append(colls, load.Coll)
	}

	tus.CheckSensorLoad(colls, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}
