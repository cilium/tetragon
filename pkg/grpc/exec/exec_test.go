// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CGO_LDFLAGS=-L$(realpath ./lib) go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo LD_LIBRARY_PATH=$(realpath ./lib) ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
)

var (
	AllEvents []*tetragon.GetEventsResponse
)

type DummyNotifier struct {
	t *testing.T
}

func (n DummyNotifier) AddListener(listener server.Listener) {}

func (n DummyNotifier) RemoveListener(listener server.Listener) {}

func (n DummyNotifier) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case *MsgExitEventUnix:
		e := v.HandleMessage()
		if e != nil {
			AllEvents = append(AllEvents, e)
		}
	case *MsgExecveEventUnix:
		e := v.HandleMessage()
		if e != nil {
			AllEvents = append(AllEvents, e)
		}
	default:
		n.t.Fatalf("Unknown type in NotifyListener = %T", v)
	}
}

type DummyObserver struct {
	t *testing.T
}

func (o DummyObserver) AddTracingPolicy(ctx context.Context, sensorName string, spec interface{}) error {
	return nil
}

func (o DummyObserver) DelTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (o DummyObserver) EnableSensor(ctx context.Context, name string) error {
	return nil
}

func (o DummyObserver) DisableSensor(ctx context.Context, name string) error {
	return nil
}

func (o DummyObserver) ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error) {
	return nil, nil
}

func (o DummyObserver) GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error) {
	return "<dummy>", nil
}

func (o DummyObserver) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	return nil
}

func (o DummyObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func createEvents(Pid uint32, Ktime uint64) (*MsgExecveEventUnix, *MsgExitEventUnix) {
	execMsg := &MsgExecveEventUnix{MsgExecveEventUnix: tetragonAPI.MsgExecveEventUnix{
		Common: tetragonAPI.MsgCommon{
			Op:     5,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   326,
			Ktime:  21034975106173,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			NetNS:  4026531992,
			Cid:    0,
			Cgrpid: 0,
			Docker: "",
		},
		Parent: tetragonAPI.MsgExecveKey{
			Pid:   1459,
			Pad:   0,
			Ktime: 75200000000,
		},
		ParentFlags: 0,
		Process: tetragonAPI.MsgProcess{
			Size:     78,
			PID:      Pid,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    Ktime,
			Filename: "/usr/bin/ls",
			Args:     "--color=auto\x00/home/apapag/tetragon",
		},
	},
	}

	exitMsg := &MsgExitEventUnix{MsgExitEvent: tetragonAPI.MsgExitEvent{
		Common: tetragonAPI.MsgCommon{
			Op:     7,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  21034976281104,
		},
		ProcessKey: tetragonAPI.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
		Info: tetragonAPI.MsgExitInfo{
			Code: 0,
			Pad1: 0, // Cached
		},
	},
	}

	return execMsg, exitMsg
}

func initEnv(t *testing.T, cancelWg *sync.WaitGroup) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	watcher := watcher.NewFakeK8sWatcher(nil)
	_, err := cilium.InitCiliumState(ctx, false)
	if err != nil {
		t.Fatalf("failed to call cilium.InitCiliumState %s", err)
	}

	if err := process.InitCache(ctx, watcher, false, 65536); err != nil {
		t.Fatalf("failed to call process.InitCache %s", err)
	}

	dn := DummyNotifier{t}
	do := DummyObserver{t}
	lServer := server.NewServer(ctx, cancelWg, dn, do)

	// Exec cache is always needed to ensure events have an associated Process{}
	eventcache.NewWithTimer(lServer, time.Millisecond*200)

	return cancel
}

func TestGrpcExecOutOfOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	cancel := initEnv(t, &cancelWg)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	execMsg, exitMsg := createEvents(46983, 21034975089403)

	e1 := exitMsg.HandleMessage()
	if e1 != nil {
		AllEvents = append(AllEvents, e1)
	}

	e2 := execMsg.HandleMessage()
	if e2 != nil {
		AllEvents = append(AllEvents, e2)
	}

	time.Sleep(time.Millisecond * 1000) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 2)

	var ev1, ev2 *tetragon.GetEventsResponse
	if AllEvents[0].GetProcessExec() != nil {
		ev1 = AllEvents[0]
		ev2 = AllEvents[1]
	} else {
		ev2 = AllEvents[0]
		ev1 = AllEvents[1]
	}

	// fails but we don't expect to have the same Refcnt
	ev1.GetProcessExec().Process.Refcnt = 0 // hardcode that to make the following pass
	assert.Equal(t, ev1.GetProcessExec().Process, ev2.GetProcessExit().Process)

	// success
	assert.Equal(t, ev1.GetProcessExec().Parent, ev2.GetProcessExit().Parent)
}

func TestGrpcExecInOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	cancel := initEnv(t, &cancelWg)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	execMsg, exitMsg := createEvents(46984, 21034975089403)

	e2 := execMsg.HandleMessage()
	if e2 != nil {
		AllEvents = append(AllEvents, e2)
	}

	e1 := exitMsg.HandleMessage()
	if e1 != nil {
		AllEvents = append(AllEvents, e1)
	}

	time.Sleep(time.Millisecond * 1000) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 2)

	var ev1, ev2 *tetragon.GetEventsResponse
	if AllEvents[0].GetProcessExec() != nil {
		ev1 = AllEvents[0]
		ev2 = AllEvents[1]
	} else {
		ev2 = AllEvents[0]
		ev1 = AllEvents[1]
	}

	// fails but we don't expect to have the same Refcnt
	ev1.GetProcessExec().Process.Refcnt = 0 // hardcode that to make the following pass
	assert.Equal(t, ev1.GetProcessExec().Process, ev2.GetProcessExit().Process)

	// success
	assert.Equal(t, ev1.GetProcessExec().Parent, ev2.GetProcessExit().Parent)
}
