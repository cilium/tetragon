// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package test

// Test sensor that uses an lseek hook that generates TEST events when BogusFd
// and BogusWhenceVal are used.

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"sync/atomic"

	"github.com/cilium/tetragon/pkg/api/ops"
	api "github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/grpc/test"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (

	// BogusFd is the fd value required to trigger the lseek test probe
	BogusFd = -1
	// BogusWhenceVal is the whence value required to trigger the lseek test probe
	BogusWhenceVal = 4729
)

var (
	// (atomic) counter for sensor names. Initialized at 0 so that first sensor is "1"
	sensorCounter uint64
)

func init() {
	AddTest()
}
func AddTest() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TEST, handleTest)
}

func msgToTestUnix(m *api.MsgTestEvent) *test.MsgTestEventUnix {
	return &test.MsgTestEventUnix{
		MsgTestEvent: *m,
	}
}

func handleTest(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgTestEvent{}
	if err := binary.Read(r, binary.LittleEndian, &m); err != nil {
		return nil, err
	}
	msgUnix := msgToTestUnix(&m)
	return []observer.Event{msgUnix}, nil
}

// GetTestSensor creates a new test sensor.
func GetTestSensor() *sensors.Sensor {
	sensorName := fmt.Sprintf("test-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
	progs := []*program.Program{program.Builder(
		"bpf_lseek.o",
		"syscalls/sys_enter_lseek",
		"tracepoint/sys_enter_lseek",
		sensors.PathJoin(sensorName, "test_lseek_prog"),
		"tracepoint",
	)}
	maps := []*program.Map{}
	sensor := &sensors.Sensor{Name: sensorName, Progs: progs, Maps: maps}
	return sensor
}
