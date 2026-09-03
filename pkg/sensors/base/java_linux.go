// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package base

import (
	"errors"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

const (
	JavaMapName       = "tg_java_urb"
	JavaTimerMapName  = "tg_java_timers"
	JavaMapSize       = 65536
	JavaTimerInterval = 1000000
)

func registerJava(sensor *sensors.Sensor) (*sensors.Sensor, error) {
	prog := program.Builder(
		"bpf_java.o",
		"",
		"syscall",
		"java_timer",
		"syscall",
	).SetPolicy(sensors.BaseSensorName)

	var eventsMap, execveMap *program.Map
	for _, m := range sensor.Maps {
		switch m.Name {
		case RingBufMapName:
			eventsMap = m
		case ExecveMap.Name:
			execveMap = m
		}
	}
	if eventsMap == nil {
		return sensor, errors.New("Java monitoring requires tg_rb_events")
	}
	if execveMap == nil {
		return sensor, errors.New("Java monitoring requires execve_map")
	}
	prog.PinMap[eventsMap.Name] = eventsMap
	prog.PinMap[execveMap.Name] = execveMap

	producerMap := program.MapBuilder(JavaMapName, prog)
	producerMap.SetMaxEntries(JavaMapSize)
	timerMap := program.MapBuilderProgram(JavaTimerMapName, prog)

	sensor.Progs = append(sensor.Progs, prog)
	sensor.Maps = append(sensor.Maps, producerMap, timerMap)
	return sensor, nil
}

func init() {
	RegisterExtensionAtInit("java_monitoring", registerJava)
}
