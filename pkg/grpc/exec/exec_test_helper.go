// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CacheTimerMs = 1
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
	t  *testing.T
	ch chan bool
}

func NewDummyNotifier[EXEC notify.Message, EXIT notify.Message](t *testing.T) DummyNotifier[EXEC, EXIT] {
	ch := make(chan bool)
	return DummyNotifier[EXEC, EXIT]{t: t, ch: ch}
}

// Wait for specified number of events from notifier
func (n DummyNotifier[EXEC, EXIT]) WaitNotifier(events int) {
	// Leave extra 100ms timeout for slow servers hiccups
	ms := time.Duration((option.Config.EventCacheNumRetries + 100) * CacheTimerMs)

	ticker := time.NewTicker(time.Millisecond * ms)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			return
		case <-n.ch:
			events--
			if events == 0 {
				return
			}
		}
	}
}

// Kick from notifier that unblocks one event for WaitNotifier
func (n DummyNotifier[EXEC, EXIT]) KickNotifier() {
	select {
	case n.ch <- true:
	default:
	}
}

func (n DummyNotifier[EXEC, EXIT]) AddListener(_ server.Listener) {}

func (n DummyNotifier[EXEC, EXIT]) RemoveListener(_ server.Listener) {}

func (n DummyNotifier[EXEC, EXIT]) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case EXEC, EXIT:
		if processed != nil {
			AllEvents = append(AllEvents, processed)
			n.KickNotifier()
		} else {
			n.t.Fatalf("Processed arg is nil in NotifyListener with type %T", v)
		}
	default:
		n.t.Fatalf("Unknown type in NotifyListener = %T", v)
	}
}

func CreateEvents[EXEC notify.Message, EXIT notify.Message](Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64, Docker string) (*EXEC, *EXEC, *EXEC, *EXIT) {
	// Create a parent event to hand events off of and convince execCache that parents are known. In order for this to
	// work we set the Pid == 1 here so that system believes this is the root of the tree.
	rootEv := tetragonAPI.MsgExecveEventUnix{
		Msg: &tetragonAPI.MsgExecveEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     5,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   326,
				Ktime:  0,
			},
			Kube: tetragonAPI.MsgK8s{
				Cgrpid: 0,
			},
			Parent: tetragonAPI.MsgExecveKey{
				Pid:   0,
				Pad:   0,
				Ktime: 0,
			},
			ParentFlags: 0,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: "",
		},
		Process: tetragonAPI.MsgProcess{
			Size:       78,
			PID:        1,
			NSPID:      0,
			SecureExec: 0,
			UID:        1010,
			AUID:       1010,
			Flags:      16385,
			Ktime:      0,
			Filename:   "init",
			Args:       "",
		},
	}

	var execRootMsg EXEC
	execRootMsg = execRootMsg.Cast(rootEv).(EXEC)

	parentEv := tetragonAPI.MsgExecveEventUnix{
		Msg: &tetragonAPI.MsgExecveEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     5,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   326,
				Ktime:  21034975106173,
			},
			Kube: tetragonAPI.MsgK8s{
				Cgrpid: 0,
			},
			Parent: tetragonAPI.MsgExecveKey{
				Pid:   1,
				Pad:   0,
				Ktime: 0,
			},
			ParentFlags: 0,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: Docker,
		},
		Process: tetragonAPI.MsgProcess{
			Size:       78,
			PID:        ParentPid,
			NSPID:      0,
			SecureExec: 0,
			UID:        1010,
			AUID:       1010,
			Flags:      16385,
			Ktime:      ParentKtime,
			Filename:   "/usr/bin/bash",
			Args:       "--color=auto\x00/home/apapag/tetragon",
		},
	}

	var execParentMsg EXEC
	execParentMsg = execParentMsg.Cast(parentEv).(EXEC)

	execEv := tetragonAPI.MsgExecveEventUnix{
		Msg: &tetragonAPI.MsgExecveEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     5,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   326,
				Ktime:  21034975106173,
			},
			Kube: tetragonAPI.MsgK8s{
				Cgrpid: 0,
			},
			Parent: tetragonAPI.MsgExecveKey{
				Pid:   ParentPid,
				Pad:   0,
				Ktime: ParentKtime,
			},
			ParentFlags: 0,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: Docker,
		},
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
			Tid:  Pid,
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
			Tid:  Pid,
		},
	}

	var exitMsg EXIT
	exitMsg = exitMsg.Cast(exitEv).(EXIT)

	return &cloneMsg, &exitMsg
}

func CreateAncestorEvents[EXEC notify.Message, EXIT notify.Message](
	Filename string,
	Pid uint32,
	Ktime uint64,
	ParentPid uint32,
	ParentKtime uint64,
	CleanupKtime uint64,
	Docker string,
) (*EXEC, *EXIT) {
	execEv := tetragonAPI.MsgExecveEventUnix{
		Msg: &tetragonAPI.MsgExecveEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     5,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   326,
				Ktime:  Ktime + 1200000,
			},
			Kube: tetragonAPI.MsgK8s{
				Cgrpid: 0,
			},
			Parent: tetragonAPI.MsgExecveKey{
				Pid:   ParentPid,
				Pad:   0,
				Ktime: ParentKtime,
			},
			ParentFlags: 0,
			CleanupProcess: tetragonAPI.MsgExecveKey{
				Pid:   Pid,
				Pad:   0,
				Ktime: CleanupKtime,
			},
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: Docker,
		},
		Process: tetragonAPI.MsgProcess{
			Size:     78,
			PID:      Pid,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    Ktime,
			Filename: Filename,
			Args:     "",
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
			Ktime:  Ktime + 20000000,
		},
		ProcessKey: tetragonAPI.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
		Info: tetragonAPI.MsgExitInfo{
			Code: 0,
			Tid:  Pid,
		},
	}

	var exitMsg EXIT
	exitMsg = exitMsg.Cast(exitEv).(EXIT)

	return &execMsg, &exitMsg
}

func InitEnv[EXEC notify.Message, EXIT notify.Message](t *testing.T, watcher watcher.PodAccessor) DummyNotifier[EXEC, EXIT] {
	if err := process.InitCache(watcher, 65536, defaults.DefaultProcessCacheGCInterval); err != nil {
		t.Fatalf("failed to call process.InitCache %s", err)
	}

	dn := NewDummyNotifier[EXEC, EXIT](t)

	// Exec cache is always needed to ensure events have an associated Process{}
	eventcache.NewWithTimer(dn, time.Millisecond*CacheTimerMs)

	return dn
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
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

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

	dn.WaitNotifier(4)
	CheckExecEvents(t, AllEvents, parentPid, currentPid)
}

func GrpcExecInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	InitEnv[EXEC, EXIT](t, watcher)

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
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	_, _, execMsg, _ := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	if !assert.Equal(t, 1, len(AllEvents)) {
		t.FailNow()
	}
	execEv := AllEvents[0].GetProcessExec()
	assert.NotNil(t, execEv)
	assert.Equal(t, GetProcessRefcntFromCache(t, currentPid, 21034975089403), uint32(1))
	assert.Nil(t, execEv.Parent)
}

func GrpcMissingExec[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

	parentPid := atomic.AddUint32(&BasePid, 1)
	currentPid := atomic.AddUint32(&BasePid, 1)

	_, _, _, exitMsg := CreateEvents[EXEC, EXIT](currentPid, 21034975089403, parentPid, 75200000000, "")

	if e := (*exitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(2)

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
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	InitEnv[EXEC, EXIT](t, watcher)

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
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	InitEnv[EXEC, EXIT](t, watcher)

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
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

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

	dn.WaitNotifier(3)

	CheckCloneEvents(t, AllEvents, currentPid, clonePid)
}

func GrpcParentInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	InitEnv[EXEC, EXIT](t, watcher)

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
	if !assert.Equal(t, 2, len(events)) {
		t.FailNow()
	}

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
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return
	dn.WaitNotifier(2)           // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exec event (out-of-order) and we
// also miss Pod info. Both of these go through the eventcache to get the
// pod info and process info. At the end both should have correct pod info
// and the exit event should also have full process info.
func GrpcExecPodInfoOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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
	dn.WaitNotifier(2) // wait for cache to do it's work
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
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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

	dn.WaitNotifier(2) // wait for cache to do it's work
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
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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

	dn.WaitNotifier(2) // wait for cache to do it's work
	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exec event (out-of-order). During
// the exit event we also miss pod info. We get pod info after at least one
// cache GC round. In this case exit event should go through the
// eventcache (missed pod and process info). Once we get the exec info
// we still have to keep the exit event in the eventcache.
func GrpcExecPodInfoDelayedOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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

	if !assert.Equal(t, 0, len(AllEvents)) { // here we should still not have any events as we don't have the podinfo yet
		t.FailNow()
	}

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	dn.WaitNotifier(2) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exec and an exit event (in-order). During
// both events we also miss pod info. We get pod info after at least one
// cache GC round.
func GrpcExecPodInfoDelayedInOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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

	if !assert.Equal(t, 0, len(AllEvents)) { // here we should still not have any events as we don't have the podinfo yet
		t.FailNow()
	}

	fakeWatcher.AddPod(dummyPod) // setup some dummy pod to return

	dn.WaitNotifier(2) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}

// In this case, we get an exit and an exex event (out-of-order).
// We get the appopriate pod info after the exit event.
func GrpcDelayedExecK8sOutOfOrder[EXEC notify.Message, EXIT notify.Message](t *testing.T) {
	AllEvents = nil
	option.Config.EnableK8s = true // enable Kubernetes
	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, fakeWatcher)

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
	if !assert.Equal(t, len(AllEvents), 0) {          // here we should still not have any events as we don't have the podinfo yet
		t.FailNow()
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(2) // wait for cache to do it's work

	CheckPodEvents(t, AllEvents)
}

func GrpcExecAncestorsInOrder[EXEC notify.Message, CLONE notify.Message, EXIT notify.Message](t *testing.T) {
	option.Config.EnableProcessAncestors = true // enable Ancestors
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

	rootPid := uint32(1)
	aPid := uint32(2)
	bPid := uint32(3)
	cPid := uint32(4)
	dPid := uint32(4)
	ePid := uint32(4)

	rootExecMsg, _, _, _ := CreateEvents[EXEC, EXIT](0, 0, rootPid, 0, "")
	rootCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](aPid, 21034975089403, rootPid, 0)
	aExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/a", aPid, 21034975089487, rootPid, 0, 21034975089403, "")
	aCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](bPid, 21034975096374, aPid, 21034975089487)
	bExecMsg, bExitMsg := CreateAncestorEvents[EXEC, EXIT]("/usr/b", bPid, 21034975097238, aPid, 21034975089487, 21034975096374, "")
	bCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](cPid, 21034975100084, bPid, 21034975097238)
	cExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/c", cPid, 21034975112851, bPid, 21034975097238, 21034975100084, "")
	dExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/d", dPid, 21034975123672, cPid, 21034975112851, 21034975112851, "")
	eExecMsg, eExitMsg := CreateAncestorEvents[EXEC, EXIT]("/usr/e", ePid, 21034975145167, dPid, 21034975123672, 21034975123672, "")

	if e := (*rootExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	(*rootCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*aExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(2)

	assert.Equal(t, 2, len(AllEvents))

	rootExecEv := AllEvents[0].GetProcessExec()
	aExecEv := AllEvents[1].GetProcessExec()

	assert.NotNil(t, rootExecEv)
	assert.NotNil(t, aExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 [+2 from parent | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 [+1 from clone  | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //exec    /usr/a    pid=2 exec_id=3 refCnt=1 [+1 from exec]
	assert.Nil(t, rootExecEv.Ancestors)                                            //process with pid=1 should not have any ancestors
	assert.Nil(t, aExecEv.Ancestors)                                               //process with pid=2 should not have any ancestors

	(*aCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*bExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 3, len(AllEvents))
	bExecEv := AllEvents[2].GetProcessExec()
	assert.NotNil(t, bExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [+2 from parent | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 [+1 from clone  | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //exec    /usr/b    pid=3 exec_id=5 refCnt=1 [+1 from exec]
	assert.Nil(t, bExecEv.Ancestors)

	(*bCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*cExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 4, len(AllEvents))
	cExecEv := AllEvents[3].GetProcessExec()
	assert.NotNil(t, cExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(3), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=3 [+2 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=2 [+2 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 [+1 from clone     | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //exec    /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from exec]
	assert.Equal(t, 1, len(cExecEv.Ancestors))
	assert.Equal(t, uint32(2), cExecEv.Ancestors[len(cExecEv.Ancestors)-1].Pid.Value)

	if e := (*dExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 5, len(AllEvents))
	dExecEv := AllEvents[4].GetProcessExec()
	assert.NotNil(t, dExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(3), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=3 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=2 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //exec    /usr/d    pid=4 exec_id=8 refCnt=1 [+1 from exec]
	assert.Equal(t, 2, len(dExecEv.Ancestors))
	assert.Equal(t, uint32(2), dExecEv.Ancestors[len(dExecEv.Ancestors)-1].Pid.Value)

	if e := (*eExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 6, len(AllEvents))
	eExecEv := AllEvents[5].GetProcessExec()
	assert.NotNil(t, eExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(3), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=3 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=2 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //        /usr/d    pid=4 exec_id=8 refCnt=1 [+1 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, ePid, 21034975145167)) //exec    /usr/e    pid=4 exec_id=9 refCnt=1 [+1 from exec]
	assert.Equal(t, 3, len(eExecEv.Ancestors))
	assert.Equal(t, uint32(2), eExecEv.Ancestors[len(eExecEv.Ancestors)-1].Pid.Value)

	if e := (*eExitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 7, len(AllEvents))
	eExitEv := AllEvents[6].GetProcessExit()
	assert.NotNil(t, eExitEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=1 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=0 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //        /usr/d    pid=4 exec_id=8 refCnt=0 [-1 from parent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, ePid, 21034975145167)) //exit    /usr/e    pid=4 exec_id=9 refCnt=0 [-1 from exit]
	assert.Equal(t, 3, len(eExitEv.Ancestors))
	assert.Equal(t, uint32(2), eExitEv.Ancestors[len(eExitEv.Ancestors)-1].Pid.Value)

	if e := (*bExitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 8, len(AllEvents))
	bExitEv := AllEvents[7].GetProcessExit()
	assert.NotNil(t, bExitEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=1 [-1 from parent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //exit    /usr/b    pid=3 exec_id=5 refCnt=0 [-1 from exit]
	assert.Nil(t, bExitEv.Ancestors)
}

func GrpcExecAncestorsOutOfOrder[EXEC notify.Message, CLONE notify.Message, EXIT notify.Message](t *testing.T) {
	option.Config.EnableProcessAncestors = true // enable Ancestors
	AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	dn := InitEnv[EXEC, EXIT](t, watcher)

	rootPid := uint32(1)
	aPid := uint32(2)
	bPid := uint32(3)
	cPid := uint32(4)
	dPid := uint32(4)
	ePid := uint32(4)

	rootExecMsg, _, _, _ := CreateEvents[EXEC, EXIT](0, 0, rootPid, 0, "")
	rootCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](aPid, 21034975089403, rootPid, 0)
	aExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/a", aPid, 21034975089487, rootPid, 0, 21034975089403, "")
	aCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](bPid, 21034975096374, aPid, 21034975089487)
	bExecMsg, bExitMsg := CreateAncestorEvents[EXEC, EXIT]("/usr/b", bPid, 21034975097238, aPid, 21034975089487, 21034975096374, "")
	bCloneMsg, _ := CreateCloneEvents[CLONE, EXIT](cPid, 21034975100084, bPid, 21034975097238)
	cExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/c", cPid, 21034975112851, bPid, 21034975097238, 21034975100084, "")
	dExecMsg, _ := CreateAncestorEvents[EXEC, EXIT]("/usr/d", dPid, 21034975123672, cPid, 21034975112851, 21034975112851, "")
	eExecMsg, eExitMsg := CreateAncestorEvents[EXEC, EXIT]("/usr/e", ePid, 21034975145167, dPid, 21034975123672, 21034975123672, "")

	if e := (*rootExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	(*rootCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*aExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(2)

	assert.Equal(t, 2, len(AllEvents))

	rootExecEv := AllEvents[0].GetProcessExec()
	aExecEv := AllEvents[1].GetProcessExec()

	assert.NotNil(t, rootExecEv)
	assert.NotNil(t, aExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 [+2 from parent | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 [+1 from clone  | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //exec    /usr/a    pid=2 exec_id=3 refCnt=1 [+1 from exec]
	assert.Nil(t, rootExecEv.Ancestors)                                            //process with pid=1 should not have any ancestors
	assert.Nil(t, aExecEv.Ancestors)                                               //process with pid=2 should not have any ancestors

	(*aCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*bExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 3, len(AllEvents))
	bExecEv := AllEvents[2].GetProcessExec()
	assert.NotNil(t, bExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [+2 from parent | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 [+1 from clone  | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //exec    /usr/b    pid=3 exec_id=5 refCnt=1 [+1 from exec]
	assert.Nil(t, bExecEv.Ancestors)

	(*bCloneMsg).HandleMessage() // does not return anything and not produces any event

	if e := (*cExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 4, len(AllEvents))
	cExecEv := AllEvents[3].GetProcessExec()
	assert.NotNil(t, cExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(3), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=3 [+2 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=2 [+2 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 [+1 from clone     | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //exec    /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from exec]
	assert.Equal(t, 1, len(cExecEv.Ancestors))
	assert.Equal(t, uint32(2), cExecEv.Ancestors[len(cExecEv.Ancestors)-1].Pid.Value)

	if e := (*bExitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 5, len(AllEvents))
	bExitEv := AllEvents[4].GetProcessExit()
	assert.NotNil(t, bExitEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [-1 from parent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //exit    /usr/b    pid=3 exec_id=5 refCnt=1 [-1 from exit]
	assert.Nil(t, bExitEv.Ancestors)

	if e := (*dExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 6, len(AllEvents))
	dExecEv := AllEvents[5].GetProcessExec()
	assert.NotNil(t, dExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=1 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //exec    /usr/d    pid=4 exec_id=8 refCnt=1 [+1 from exec]
	assert.Equal(t, 2, len(dExecEv.Ancestors))
	assert.Equal(t, uint32(2), dExecEv.Ancestors[len(dExecEv.Ancestors)-1].Pid.Value)

	if e := (*eExecMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 7, len(AllEvents))
	eExecEv := AllEvents[6].GetProcessExec()
	assert.NotNil(t, eExecEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=2 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=2 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=1 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=1 [+1 from Ancestors | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //        /usr/d    pid=4 exec_id=8 refCnt=1 [+1 from parent    | -1 from CleanupEvent]
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, ePid, 21034975145167)) //exec    /usr/e    pid=4 exec_id=9 refCnt=1 [+1 from exec]
	assert.Equal(t, 3, len(eExecEv.Ancestors))
	assert.Equal(t, uint32(2), eExecEv.Ancestors[len(eExecEv.Ancestors)-1].Pid.Value)

	if e := (*eExitMsg).HandleMessage(); e != nil {
		AllEvents = append(AllEvents, e)
	}

	dn.WaitNotifier(1)

	assert.Equal(t, 8, len(AllEvents))
	eExitEv := AllEvents[7].GetProcessExit()
	assert.NotNil(t, eExitEv)

	assert.Equal(t, uint32(2), GetProcessRefcntFromCache(t, rootPid, 0))           //        /usr/init pid=1 exec_id=1 refCnt=1 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, aPid, 21034975089403)) //        /usr/init pid=2 exec_id=2 refCnt=0 []
	assert.Equal(t, uint32(1), GetProcessRefcntFromCache(t, aPid, 21034975089487)) //        /usr/a    pid=2 exec_id=3 refCnt=1 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975096374)) //        /usr/a    pid=3 exec_id=4 refCnt=0 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, bPid, 21034975097238)) //        /usr/b    pid=3 exec_id=5 refCnt=0 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975100084)) //        /usr/b    pid=4 exec_id=6 refCnt=0 []
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, cPid, 21034975112851)) //        /usr/c    pid=4 exec_id=7 refCnt=0 [-1 from Ancestors]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, dPid, 21034975123672)) //        /usr/d    pid=4 exec_id=8 refCnt=0 [-1 from parent]
	assert.Equal(t, uint32(0), GetProcessRefcntFromCache(t, ePid, 21034975145167)) //exit    /usr/e    pid=4 exec_id=9 refCnt=0 [-1 from exit]
	assert.Equal(t, 3, len(eExitEv.Ancestors))
	assert.Equal(t, uint32(2), eExitEv.Ancestors[len(eExitEv.Ancestors)-1].Pid.Value)
}
