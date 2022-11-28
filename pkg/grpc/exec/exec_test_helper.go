// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CacheTimerMs = 100
)

var (
	AllEvents []*tetragon.GetEventsResponse
	BasePid   uint32 = 46987
	dummyPod         = &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "fake_pod_namespace",
			Name:      "fake_pod_name",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					ContainerID: "docker://fake_container_container_id",
					Name:        "fake_container_name",
					Image:       "fake_container_image",
					ImageID:     "fake_container_image_id",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: v1.Time{
								Time: time.Unix(21034995089403, 0),
							},
						},
					},
				},
			},
		},
	}
)

type DummyNotifier[EXEC notify.Message, EXIT notify.Message] struct {
	t *testing.T
}

func (n DummyNotifier[EXEC, EXIT]) AddListener(listener server.Listener) {}

func (n DummyNotifier[EXEC, EXIT]) RemoveListener(listener server.Listener) {}

func (n DummyNotifier[EXEC, EXIT]) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case EXEC, EXIT:
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

func CreateEvents[EXEC notify.Message, EXIT notify.Message](Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64, Docker string) (*EXEC, *EXEC, *EXEC, *EXIT) {
	// Create a parent event to hand events off of and convince execCache that parents are known. In order for this to
	// work we set the Pid == 1 here so that system believes this is the root of the tree.
	rootEv := tetragonAPI.MsgExecveEventUnix{
		Common: tetragonAPI.MsgCommon{
			Op:     5,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   326,
			Ktime:  0,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			NetNS:  0,
			Cid:    0,
			Cgrpid: 0,
			Docker: "",
		},
		Parent: tetragonAPI.MsgExecveKey{
			Pid:   0,
			Pad:   0,
			Ktime: 0,
		},
		ParentFlags: 0,
		Process: tetragonAPI.MsgProcess{
			Size:     78,
			PID:      1,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    0,
			Filename: "init",
			Args:     "",
		},
	}

	var execRootMsg EXEC
	execRootMsg = execRootMsg.Cast(rootEv).(EXEC)

	parentEv := tetragonAPI.MsgExecveEventUnix{
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
			Pid:   1,
			Pad:   0,
			Ktime: 0,
		},
		ParentFlags: 0,
		Process: tetragonAPI.MsgProcess{
			Size:     78,
			PID:      ParentPid,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    ParentKtime,
			Filename: "/usr/bin/bash",
			Args:     "--color=auto\x00/home/apapag/tetragon",
		},
	}

	var execParentMsg EXEC
	execParentMsg = execParentMsg.Cast(parentEv).(EXEC)

	execEv := tetragonAPI.MsgExecveEventUnix{
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
	}

	var execMsg EXEC
	execMsg = execMsg.Cast(execEv).(EXEC)

	exitEv := tetragonAPI.MsgExitEvent{
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
	}

	var exitMsg EXIT
	exitMsg = exitMsg.Cast(exitEv).(EXIT)

	return &execRootMsg, &execParentMsg, &execMsg, &exitMsg
}

func CreateCloneEvents[CLONE notify.Message, EXIT notify.Message](Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64) (*CLONE, *EXIT) {
	cloneEv := tetragonAPI.MsgCloneEvent{
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
	}

	var cloneMsg CLONE
	cloneMsg = cloneMsg.Cast(cloneEv).(CLONE)

	exitEv := tetragonAPI.MsgExitEvent{
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
	}

	var exitMsg EXIT
	exitMsg = exitMsg.Cast(exitEv).(EXIT)

	return &cloneMsg, &exitMsg
}

func InitEnv[EXEC notify.Message, EXIT notify.Message](t *testing.T, cancelWg *sync.WaitGroup, watcher watcher.K8sResourceWatcher) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	_, err := cilium.InitCiliumState(ctx, false)
	if err != nil {
		t.Fatalf("failed to call cilium.InitCiliumState %s", err)
	}

	if err := process.InitCache(ctx, watcher, false, 65536); err != nil {
		t.Fatalf("failed to call process.InitCache %s", err)
	}

	dn := DummyNotifier[EXEC, EXIT]{t}
	do := DummyObserver{t}
	lServer := server.NewServer(ctx, cancelWg, dn, do)

	// Exec cache is always needed to ensure events have an associated Process{}
	eventcache.NewWithTimer(lServer, time.Millisecond*CacheTimerMs)

	return cancel
}

func GetProcessRefcntFromCache(t *testing.T, Pid uint32, Ktime uint64) uint32 {
	procID := process.GetProcessID(Pid, Ktime)
	proc, err := process.Get(procID)
	if err == nil {
		return proc.RefGet()
	}

	t.Fatalf("failed to find a process in the procCache pid: %d, ktime: %d, ID: %s ", Pid, Ktime, err)
	return 0
}

func GetEvents(t *testing.T, events []*tetragon.GetEventsResponse) (*tetragon.ProcessExec, *tetragon.ProcessExit) {
	assert.Equal(t, len(events), 2)

	var execEv *tetragon.ProcessExec
	var exitEv *tetragon.ProcessExit

	if events[0].GetProcessExec() != nil {
		execEv = events[0].GetProcessExec()
		exitEv = events[1].GetProcessExit()
	} else {
		exitEv = events[0].GetProcessExit()
		execEv = events[1].GetProcessExec()
	}

	return execEv, exitEv
}

func CheckProcessEqual(t *testing.T, p1, p2 *tetragon.Process) {
	assert.Equal(t, p1.ExecId, p2.ExecId)
	assert.Equal(t, p1.Pid, p2.Pid)
	assert.Equal(t, p1.Uid, p2.Uid)
	assert.Equal(t, p1.Cwd, p2.Cwd)
	assert.Equal(t, p1.Binary, p2.Binary)
	assert.Equal(t, p1.Arguments, p2.Arguments)
	assert.Equal(t, p1.Flags, p2.Flags)
	assert.Equal(t, p1.StartTime, p2.StartTime)
	assert.Equal(t, p1.Auid, p2.Auid)
	assert.Equal(t, p1.Pod, p2.Pod)
	assert.Equal(t, p1.Docker, p2.Docker)
	assert.Equal(t, p1.ParentExecId, p2.ParentExecId)
	assert.Equal(t, p1.Cap, p2.Cap)
	assert.Equal(t, p1.Ns, p2.Ns)
}

func CheckExecEvents(t *testing.T, events []*tetragon.GetEventsResponse, parentPid uint32, currentPid uint32) {
	assert.Equal(t, len(events), 4)

	var execRootEv, execParentEv, execEv *tetragon.ProcessExec
	var exitEv *tetragon.ProcessExit

	for _, ev := range events {
		if ev.GetProcessExec() != nil {
			tmp := ev.GetProcessExec()
			if tmp.Process.Pid.Value == uint32(1) {
				execRootEv = tmp
			} else if tmp.Process.Pid.Value == uint32(parentPid) {
				execParentEv = tmp
			} else if tmp.Process.Pid.Value == uint32(currentPid) {
				execEv = tmp
			}

		} else {
			exitEv = ev.GetProcessExit()
		}
	}

	assert.NotNil(t, execRootEv)
	assert.NotNil(t, execParentEv)
	assert.NotNil(t, execEv)
	assert.NotNil(t, exitEv)

	assert.Equal(t, GetProcessRefcntFromCache(t, 1, 0), uint32(2))
	assert.Equal(t, GetProcessRefcntFromCache(t, parentPid, 75200000000), uint32(1))
	assert.Equal(t, GetProcessRefcntFromCache(t, currentPid, 21034975089403), uint32(0))

	// check parents
	assert.Nil(t, execRootEv.Parent)
	assert.NotNil(t, execParentEv.Parent)
	assert.NotNil(t, execEv.Parent)
	assert.NotNil(t, exitEv.Parent)

	// success
	CheckProcessEqual(t, execEv.Process, exitEv.Process)

	// success
	CheckProcessEqual(t, execEv.Parent, exitEv.Parent)
}

func GrpcExecOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*execRoot).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execParent).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work
	CheckExecEvents(t, AllEvents, parentPid, currentPid)
}

func GrpcExecInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*execRoot).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execParent).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	CheckExecEvents(t, AllEvents, parentPid, currentPid)
}

func GrpcExecMisingParent[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	_, _, execMsg, _ := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 1)
	execEv := AllEvents[0].GetProcessExec()
	assert.NotNil(t, execEv)
	assert.Equal(t, GetProcessRefcntFromCache(t, currentPid, 21034975089403), uint32(1))
	assert.Nil(t, execEv.Parent)
}

func GrpcMissingExec[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	_, _, _, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	assert.Equal(t, len(AllEvents), 1)
	ev := AllEvents[0]
	assert.NotNil(t, ev.GetProcessExit())

	// this events misses process info
	assert.Equal(t, ev.GetProcessExit().Process.ExecId, "")
	assert.Equal(t, ev.GetProcessExit().Process.Binary, "")

	// but should have a correct Pid
	assert.Equal(t, ev.GetProcessExit().Process.Pid, &wrapperspb.UInt32Value{Value: currentPid})
}

func GrpcExecParentOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	// create some corrent events to have parents
	(*execRoot).HandleMessage()
	(*execParent).HandleMessage()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	ev1, ev2 := GetEvents(t, AllEvents)

	// success
	CheckProcessEqual(t, ev1.Process, ev2.Process)

	// success
	CheckProcessEqual(t, ev1.Parent, ev2.Parent)
}

func CheckCloneEvents(t *testing.T, events []*tetragon.GetEventsResponse, currentPid uint32, clonePid uint32) {
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

func GrpcExecCloneInOrder[EXEC notify.Message, CLONE notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)
	clonePid := atomic.AddUint32(&BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")
	cloneMsg, exitCloneMsg := CreateCloneEvents[CLONE, EXIT](clonePid, 21034995089403, currentPid, 21034975089403)

	// create some corrent events to have parents
	(*execRoot).HandleMessage()
	(*execParent).HandleMessage()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	(*cloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*exitCloneMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	CheckCloneEvents(t, AllEvents, currentPid, clonePid)
}

func GrpcExecCloneOutOfOrder[EXEC notify.Message, CLONE notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)
	clonePid := atomic.AddUint32(&BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")
	cloneMsg, exitCloneMsg := CreateCloneEvents[CLONE, EXIT](clonePid, 21034995089403, currentPid, 21034975089403)

	// create some corrent events to have parents
	(*execRoot).HandleMessage()
	(*execParent).HandleMessage()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitCloneMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	(*cloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	CheckCloneEvents(t, AllEvents, currentPid, clonePid)
}

func GrpcParentInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, _, parentExecMsg, parentExitMsg := CreateEvents[EXEC, EXIT](parentPid, 75200000000, 1, 0, "")
	_, _, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	(*rootMsg).HandleMessage()

	if e := (*parentExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*parentExitMsg).HandleMessage(); e != nil {
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
	// 2. has parent
	assert.Equal(t, parentExecEv.Process.Pid.Value, parentPid)
	assert.NotNil(t, parentExecEv.Parent)

	// 2nd event: exec from child
	// 1. should match pid of child
	// 2. parent pid should match previous event's pid
	assert.Equal(t, currentExecEv.Process.Pid.Value, currentPid)
	assert.Equal(t, currentExecEv.Parent.Pid.Value, parentPid)

	// 3rd event: exit from child
	// 1. should match pid of child
	// 2. parent pid should match previous event's pid
	assert.Equal(t, currentExitEv.Process.Pid.Value, currentPid)
	assert.Equal(t, currentExitEv.Parent.Pid.Value, parentPid)

	// 4th event: exit from parent
	// 1. should match pid of parent
	// 2. has parent
	assert.Equal(t, parentExitEv.Process.Pid.Value, parentPid)
	assert.NotNil(t, parentExitEv.Parent)
}

func CheckPodEvents(t *testing.T, events []*tetragon.GetEventsResponse) {
	assert.Equal(t, len(events), 2)

	execEv, exitEv := GetEvents(t, events)

	assert.NotNil(t, execEv)
	assert.NotNil(t, execEv.Process.Pod)                                // has pod info
	assert.Equal(t, execEv.Process.Pod.Namespace, "fake_pod_namespace") // correct pod
	assert.NotEqual(t, execEv.Process.ExecId, "")                       // full process info
	assert.NotNil(t, execEv.Parent)

	assert.NotNil(t, exitEv)
	assert.NotNil(t, exitEv.Process.Pod)                                // has pod info
	assert.Equal(t, exitEv.Process.Pod.Namespace, "fake_pod_namespace") // correct pod
	assert.NotEqual(t, exitEv.Process.ExecId, "")                       // full process info
	assert.NotNil(t, exitEv.Parent)
}

// In this case, we get an exec and an exit event (in-order) but we
// miss Pod info. Both of these go through the eventcache to get the
// pod info. At the end both should have correct pod info and the exit
// event should also have full process info.
func GrpcExecPodInfoInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	fakeWatcher.AddPod(dummyPod)                                                  // setup some dummy pod to return
	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exec event (out-of-order) and we
// also miss Pod info. Both of these go through the eventcache to get the
// pod info and process info. At the end both should have correct pod info
// and the exit event should also have full process info.
func GrpcExecPodInfoOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	fakeWatcher.AddPod(dummyPod)
	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exec and an exit event (in-order). During
// the exec event we miss pod info. We get pod info before getting
// the exit event. In this case exec event should go through the
// eventcache (missed pod info) and exit event should also go through
// the cache as the procCache has not been updated yet. At the end both
// should have correct pod info and the exit event should also have full
// process info.
func GrpcExecPodInfoInOrderAfter[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exec event (out-of-order). During
// the exit event we also miss pod info. We get pod info before getting
// the exec event. In this case exit event should go through the
// eventcache (missed pod and process info) and exec event should not go
// through the cache as we have everything. At the end both should
// have correct pod info and the exit event should also have full
// process info.
func GrpcExecPodInfoOutOfOrderAfter[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return
	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exec event (out-of-order). During
// the exit event we also miss pod info. We get pod info after at least one
// cache GC round. In this case exit event should go through the
// eventcache (missed pod and process info). Once we get the exec info
// we still have to keep the exit event in the eventcache.
func GrpcExecPodInfoDelayedOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * (5 * CacheTimerMs)) // wait for cache to do it's work (but less than eventcache.CacheStrikes iterations)

	assert.Equal(t, len(AllEvents), 0) // here we should still not have any events as we don't have the podinfo yet

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exec and an exit event (in-order). During
// both events we also miss pod info. We get pod info after at least one
// cache GC round.
func GrpcExecPodInfoDelayedInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * (5 * CacheTimerMs)) // wait for cache to do it's work (but less than eventcache.CacheStrikes iterations)

	assert.Equal(t, len(AllEvents), 0) // here we should still not have any events as we don't have the podinfo yet

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exex event (out-of-order).
// We get the appopriate pod info after the exit event.
func GrpcDelayedExecK8sOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	var cancelWg sync.WaitGroup

	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	cancel := InitEnv[EXEC, EXIT](t, &cancelWg, fakeWatcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	rootMsg, parentMsg, execMsg, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "fake_container_container_id")

	// Create some corrent events to have parents
	// in the cache. We also provide a dummy pod
	// here in order not to cache these events. At
	// the end we remove pod info to do the actual
	// test.
	fakeWatcher.AddPod(dummyPod)
	(*rootMsg).HandleMessage()
	(*parentMsg).HandleMessage()
	fakeWatcher.ClearAllPods()

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	time.Sleep(time.Millisecond * (5 * CacheTimerMs)) // wait for cache to do it's work (but less than eventcache.CacheStrikes iterations)
	assert.Equal(t, len(AllEvents), 0)                // here we should still not have any events as we don't have the podinfo yet

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * CacheTimerMs)) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}
