// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// CGO_LDFLAGS=-L$(realpath ./lib) go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo LD_LIBRARY_PATH=$(realpath ./lib) ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"context"
	"sync"
	"sync/atomic"
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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	cacheTimerMs = 100
)

var (
	AllEvents []*tetragon.GetEventsResponse
	basePid   uint32 = 46987
)

type DummyNotifier struct {
	t *testing.T
}

func (n DummyNotifier) AddListener(listener server.Listener) {}

func (n DummyNotifier) RemoveListener(listener server.Listener) {}

func (n DummyNotifier) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case *MsgExitEventUnix, *MsgExecveEventUnix:
		if processed != nil {
			AllEvents = append(AllEvents, processed)
		} else {
			n.t.Fatalf("Processed arg is nil in NotifyListener with type %T", v)
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

func createEvents(Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64, Docker string) (*MsgExecveEventUnix, *MsgExitEventUnix) {
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
			Docker: Docker,
		},
		Parent: tetragonAPI.MsgExecveKey{
			Pid:   ParentPid,
			Pad:   0,
			Ktime: ParentKtime,
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
			Pad1: 0,
		},
	},
	}

	return execMsg, exitMsg
}

func createCloneEvents(Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64) (*MsgCloneEventUnix, *MsgExitEventUnix) {
	cloneMsg := &MsgCloneEventUnix{MsgCloneEvent: tetragonAPI.MsgCloneEvent{
		Common: tetragonAPI.MsgCommon{
			Op:     23,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   326,
			Ktime:  21034975126173,
		},
		Parent: tetragonAPI.MsgExecveKey{
			Pid:   ParentPid,
			Pad:   0,
			Ktime: ParentKtime,
		},
		PID:   Pid,
		NSPID: 0,
		Flags: 16385,
		Ktime: Ktime,
	}}

	exitMsg := &MsgExitEventUnix{MsgExitEvent: tetragonAPI.MsgExitEvent{
		Common: tetragonAPI.MsgCommon{
			Op:     7,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  21034976291104,
		},
		ProcessKey: tetragonAPI.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
		Info: tetragonAPI.MsgExitInfo{
			Code: 0,
			Pad1: 0,
		},
	},
	}

	return cloneMsg, exitMsg
}

func initEnv(t *testing.T, cancelWg *sync.WaitGroup, watcher watcher.K8sResourceWatcher) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

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
	eventcache.NewWithTimer(lServer, time.Millisecond*cacheTimerMs)

	return cancel
}

func TestGrpcExecOutOfOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)

	execMsg, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := execMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * cacheTimerMs)) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 2)

	var ev1, ev2 *tetragon.GetEventsResponse
	if AllEvents[0].GetProcessExec() != nil {
		ev1 = AllEvents[0]
		ev2 = AllEvents[1]
	} else {
		ev2 = AllEvents[0]
		ev1 = AllEvents[1]
	}

	// success
	assert.Equal(t, ev1.GetProcessExec().Process, ev2.GetProcessExit().Process)

	// success
	assert.Equal(t, ev1.GetProcessExec().Parent, ev2.GetProcessExit().Parent)
}

func TestGrpcExecInOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)

	execMsg, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := execMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

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

func TestGrpcMissingExec(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)

	_, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * cacheTimerMs)) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 1)
	ev := AllEvents[0]
	assert.NotNil(t, ev.GetProcessExit())

	// this events misses process info
	assert.Equal(t, ev.GetProcessExit().Process.ExecId, "")
	assert.Equal(t, ev.GetProcessExit().Process.Binary, "")

	// but should have a correct Pid
	assert.Equal(t, ev.GetProcessExit().Process.Pid, &wrapperspb.UInt32Value{Value: currentPid})
}

func checkCloneEvents(t *testing.T, events []*tetragon.GetEventsResponse, currentPid uint32, clonePid uint32) {
	assert.Equal(t, len(events), 3)

	foundExitExecProcess := false
	foundExitCloneProcess := false
	for _, ev := range events {
		if ev.GetProcessExec() != nil {
			execEv := ev.GetProcessExec()
			assert.Equal(t, execEv.Process.Pid.Value, currentPid)
		} else if ev.GetProcessExit() != nil {
			exitEv := ev.GetProcessExit()
			assert.NotEqual(t, exitEv.Process.ExecId, "") // ensure not empty
			assert.NotEqual(t, exitEv.Process.Binary, "") // ensure not empty

			if exitEv.Process.Pid.Value == currentPid {
				foundExitExecProcess = true
			} else if exitEv.Process.Pid.Value == clonePid {
				foundExitCloneProcess = true
			} else {
				assert.Fail(t, "unknown event PID")
			}
		} else {
			assert.Fail(t, "unknown event type")
		}
	}

	assert.True(t, foundExitExecProcess)
	assert.True(t, foundExitCloneProcess)
}

func TestGrpcExecCloneInOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)
	clonePid := atomic.AddUint32(&basePid, 1)

	execMsg, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")
	cloneMsg, exitCloneMsg := createCloneEvents(clonePid, 21034995089403, currentPid, 21034975089403)

	if e := execMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	cloneMsg.HandleMessage() // does not return anything and not produces any event

	if e := exitCloneMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	checkCloneEvents(t, AllEvents, currentPid, clonePid)
}

func TestGrpcExecCloneOutOfOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)
	clonePid := atomic.AddUint32(&basePid, 1)

	execMsg, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")
	cloneMsg, exitCloneMsg := createCloneEvents(clonePid, 21034995089403, currentPid, 21034975089403)

	if e := execMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := exitCloneMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	cloneMsg.HandleMessage() // does not return anything and not produces any event

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * cacheTimerMs)) // wait for cache to do it's work

	checkCloneEvents(t, AllEvents, currentPid, clonePid)
}

func TestGrpcParentRefcntInOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&basePid, 1)
	currentPid := atomic.AddUint32(&basePid, 1)

	parentExecMsg, parentExitMsg := createEvents(parentPid, 75200000000, 0, 0, "")
	execMsg, exitMsg := createEvents(currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := parentExecMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := execMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := exitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := parentExitMsg.HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	assert.Equal(t, len(AllEvents), 4)

	parentExecEv := AllEvents[0].GetProcessExec()
	currentExecEv := AllEvents[1].GetProcessExec()
	currentExitEv := AllEvents[2].GetProcessExit()
	parentExitEv := AllEvents[3].GetProcessExit()

	assert.NotNil(t, parentExecEv)
	assert.NotNil(t, currentExecEv)
	assert.NotNil(t, currentExitEv)
	assert.NotNil(t, parentExitEv)

	// 1st event: exec from parent
	// 1. should match pid of parent
	// 2. refcount should be 1
	// 3. no parent
	assert.Equal(t, parentExecEv.Process.Pid.Value, parentPid)
	assert.Equal(t, parentExecEv.Process.Refcnt, uint32(1))
	assert.Nil(t, parentExecEv.Parent)

	// 2nd event: exec from child
	// 1. should match pid of child
	// 2. refcount should be 1
	// 3. parent pid should match previous event's pid
	// 4. parent refcount should be 2 (increased by 1 during this exec)
	assert.Equal(t, currentExecEv.Process.Pid.Value, currentPid)
	assert.Equal(t, currentExecEv.Process.Refcnt, uint32(1))
	assert.Equal(t, currentExecEv.Parent.Pid.Value, parentPid)
	assert.Equal(t, currentExecEv.Parent.Refcnt, uint32(2))

	// 3rd event: exit from child
	// 1. should match pid of child
	// 2. refcount should be 0 (decreased by 1 during this exit)
	// 3. parent pid should match previous event's pid
	// 4. parent refcount should be 2 (decreased by 1 during this exit)
	assert.Equal(t, currentExitEv.Process.Pid.Value, currentPid)
	assert.Equal(t, currentExitEv.Process.Refcnt, uint32(0))
	assert.Equal(t, currentExitEv.Parent.Pid.Value, parentPid)
	assert.Equal(t, currentExitEv.Parent.Refcnt, uint32(1))

	// 4th event: exit from parent
	// 1. should match pid of parent
	// 2. refcount should be 0 (decreased by 1 during this exit)
	// 3. no parent
	assert.Equal(t, parentExitEv.Process.Pid.Value, parentPid)
	assert.Equal(t, parentExitEv.Process.Refcnt, uint32(0))
	assert.Nil(t, parentExitEv.Parent)
}
