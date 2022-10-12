// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	readerexec "github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

const (
	ParentRefCnt  = 0
	ProcessRefCnt = 1
)

func (msg *MsgExecveEventUnix) getCleanupEvent() *MsgProcessCleanupEventUnix {
	if msg.CleanupProcess.Ktime == 0 {
		return nil
	}
	return &MsgProcessCleanupEventUnix{
		PID:   msg.CleanupProcess.Pid,
		Ktime: msg.CleanupProcess.Ktime,
	}
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func GetProcessExec(event *MsgExecveEventUnix, useCache bool) *tetragon.ProcessExec {
	var tetragonParent *tetragon.Process

	proc := process.AddExecEvent(&event.MsgExecveEventUnix)
	tetragonProcess := proc.UnsafeGetProcess()

	parentId := tetragonProcess.ParentExecId
	processId := tetragonProcess.ExecId

	parent, err := process.Get(parentId)
	if err == nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
		logger.GetLogger().WithError(err).WithField("processId", processId).WithField("parentId", parentId).Debugf("Failed to annotate process with capabilities and namespaces info")
	}

	tetragonEvent := &tetragon.ProcessExec{
		Process: tetragonProcess,
		Parent:  tetragonParent,
	}

	if useCache {
		if ec := eventcache.Get(); ec != nil &&
			(ec.Needed(tetragonEvent.Process) || (tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonEvent.Parent))) {
			ec.Add(proc, tetragonEvent, event.Common.Ktime, event)
			return nil
		}
	}

	if parent != nil {
		parent.RefInc()
		tetragonEvent.Parent = parent.GetProcessCopy()
	}

	// do we need to cleanup anything?
	if cleanupEvent := event.getCleanupEvent(); cleanupEvent != nil {
		cleanupEvent.HandleMessage()
	}

	return tetragonEvent
}

type MsgCgroupEventUnix struct {
	processapi.MsgCgroupEvent
}

func (msg *MsgCgroupEventUnix) Notify() bool {
	return false
}

func (msg *MsgCgroupEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgCgroupEventUnix RetryInternal() was called")
}

func (msg *MsgCgroupEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return fmt.Errorf("Unreachable state: MsgCgroupEventUnix Retry() was called")
}

func (msg *MsgCgroupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	switch msg.Common.Op {
	case ops.MSG_OP_CGROUP:
		op := ops.CgroupOpCode(msg.CgrpOp)
		st := ops.CgroupState(msg.CgrpData.State).String()
		switch op {
		case ops.MSG_OP_CGROUP_MKDIR, ops.MSG_OP_CGROUP_RMDIR, ops.MSG_OP_CGROUP_RELEASE:
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.event":     op.String(),
				"PID":              msg.PID,
				"NSPID":            msg.NSPID,
				"cgroup.IDTracker": msg.CgrpidTracker,
				"cgroup.ID":        msg.Cgrpid,
				"cgroup.state":     st,
				"cgroup.level":     msg.CgrpData.Level,
				"cgroup.path":      cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]),
			}).Debug("Received Cgroup event")
		case ops.MSG_OP_CGROUP_ATTACH_TASK:
			// Here we should get notification when Tetragon migrate itself
			// and discovers cgroups configuration
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.event":     op.String(),
				"PID":              msg.PID,
				"NSPID":            msg.NSPID,
				"cgroup.IDTracker": msg.CgrpidTracker,
				"cgroup.ID":        msg.Cgrpid,
				"cgroup.state":     st,
				"cgroup.level":     msg.CgrpData.Level,
				"cgroup.path":      cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]),
			}).Info("Received Cgroup event")
		default:
			logger.GetLogger().WithField("message", msg).Warn("HandleCgroupMessage: Unhandled Cgroup operation event")
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCgroupMessage: Unhandled event")
	}
	return nil
}

func (msg *MsgCgroupEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCgroupEvent)
	return &MsgCgroupEventUnix{MsgCgroupEvent: t}
}

type MsgExecveEventUnix struct {
	processapi.MsgExecveEventUnix
}

func (msg *MsgExecveEventUnix) Notify() bool {
	return true
}

func (msg *MsgExecveEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgExecveEventUnix with missing internal")
}

func (msg *MsgExecveEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	var podInfo *tetragon.Pod

	proc := ev.GetProcess()
	parent := ev.GetParent()

	containerId := proc.Docker
	filename := proc.Binary
	args := proc.Arguments
	nspid := msg.Process.NSPID

	if option.Config.EnableK8s && containerId != "" {
		podInfo, _ = process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
			return eventcache.ErrFailedToGetPodInfo
		}
	}

	// We can assume that event.internal != nil here since it's being set by AddExecEvent
	// earlier in the code path. If this invariant ever changes in the future, we probably
	// want to panic anyway to help us catch the bug faster. So no need to do a nil check
	// here.
	internal.AddPodInfo(podInfo)
	ev.SetProcess(internal.GetProcessCopy())

	// Check we have a parent with exception for pid 1, note we do this last because we want
	// to ensure the podInfo and process are set before returning any errors.
	if proc.Pid.Value > 1 && parent == nil {
		parentId := proc.ParentExecId
		parent, err := process.Get(parentId)
		if parent == nil {
			return err
		}
		parent.RefInc()
		ev.SetParent(parent.GetProcessCopy())
	}

	// do we need to cleanup anything?
	if cleanupEvent := msg.getCleanupEvent(); cleanupEvent != nil {
		// Retry() is going to be executed in the cache loop handling function, but
		// HandleMessage may enqueue something in the cache channel. To avoid a deadlock,
		// execute the cleanup message handling in a separate goroutine.
		go cleanupEvent.HandleMessage()
	}

	return nil
}

func (msg *MsgExecveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXECVE:
		if e := GetProcessExec(msg, true); e != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

func (msg *MsgExecveEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExecveEventUnix)
	return &MsgExecveEventUnix{MsgExecveEventUnix: t}
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

func (msg *MsgCloneEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, process.AddCloneEvent(&msg.MsgCloneEvent)
}

func (msg *MsgCloneEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return nil
}

func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	switch msg.Common.Op {
	case ops.MSG_OP_CLONE:
		if err := process.AddCloneEvent(&msg.MsgCloneEvent); err != nil {
			ec := eventcache.Get()
			if ec != nil {
				ec.Add(nil, nil, msg.MsgCloneEvent.Ktime, msg)
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCloneMessage: Unhandled event")
	}
	return nil
}

func (msg *MsgCloneEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCloneEvent)
	return &MsgCloneEventUnix{MsgCloneEvent: t}
}

// GetProcessExit returns Exit protobuf message for a given process.
func GetProcessExit(event *MsgExitEventUnix) *tetragon.ProcessExit {
	var tetragonProcess, tetragonParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		tetragonProcess = process.UnsafeGetProcess()
	} else {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	code := event.Info.Code >> 8
	signal := readerexec.Signal(event.Info.Code & 0xFF)

	tetragonEvent := &tetragon.ProcessExit{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Signal:  signal,
		Status:  code,
	}
	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.ProcessKey.Ktime, event)
		return nil
	}
	if parent != nil {
		parent.RefDec()
		tetragonEvent.Parent = parent.GetProcessCopy()
	}
	if process != nil {
		process.RefDec()
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

type MsgExitEventUnix struct {
	tetragonAPI.MsgExitEvent
	RefCntDone [2]bool
}

func (msg *MsgExitEventUnix) Notify() bool {
	return true
}

func (msg *MsgExitEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, timestamp)
	var err error

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec()
			msg.RefCntDone[ParentRefCnt] = true
		}
		ev.SetParent(parent.GetProcessCopy())
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec()
			msg.RefCntDone[ProcessRefCnt] = true
		}
		ev.SetProcess(internal.GetProcessCopy())
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgExitEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse

	switch msg.Common.Op {
	case ops.MSG_OP_EXIT:
		msg.RefCntDone = [2]bool{false, false}
		e := GetProcessExit(msg)
		if e != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExit{ProcessExit: e},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExitMessage: Unhandled event")
	}
	return res
}

func (msg *MsgExitEventUnix) Cast(o interface{}) notify.Message {
	t := o.(tetragonAPI.MsgExitEvent)
	return &MsgExitEventUnix{MsgExitEvent: t}
}

type MsgProcessCleanupEventUnix struct {
	PID        uint32
	Ktime      uint64
	RefCntDone [2]bool
}

func (msg *MsgProcessCleanupEventUnix) Notify() bool {
	return false
}

func (msg *MsgProcessCleanupEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternal(msg.PID, timestamp)
	var err error

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec()
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec()
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgProcessCleanupEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return nil
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	msg.RefCntDone = [2]bool{false, false}
	if process, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime); process != nil && parent != nil {
		parent.RefDec()
		process.RefDec()
	} else {
		if ec := eventcache.Get(); ec != nil {
			ec.Add(nil, nil, msg.Ktime, msg)
		}
	}
	return nil
}

func (msg *MsgProcessCleanupEventUnix) Cast(o interface{}) notify.Message {
	return &MsgProcessCleanupEventUnix{}
}
