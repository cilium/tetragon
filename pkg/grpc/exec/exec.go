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
	if msg.Unix.Msg.CleanupProcess.Ktime == 0 {
		return nil
	}
	return &MsgProcessCleanupEventUnix{
		PID:   msg.Unix.Msg.CleanupProcess.Pid,
		Ktime: msg.Unix.Msg.CleanupProcess.Ktime,
	}
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func GetProcessExec(event *MsgExecveEventUnix, useCache bool) *tetragon.ProcessExec {
	var tetragonParent *tetragon.Process

	proc := process.AddExecEvent(event.Unix)
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

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if useCache {
		if ec := eventcache.Get(); ec != nil &&
			(ec.Needed(tetragonEvent.Process) || (tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonEvent.Parent))) {
			ec.Add(proc, tetragonEvent, event.Unix.Msg.Common.Ktime, event.Unix.Process.Ktime, event)
			return nil
		}
	}

	if parent != nil {
		parent.RefInc("parent")
	}

	// Finalize the process event with extra fields
	if err := event.finalize(tetragonEvent, proc, eventcache.NO_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     tetragonProcess.GetPid().GetValue(),
			"event.process.binary":  tetragonProcess.Binary,
			"event.process.exec_id": processId,
			"event.event_cache":     "no",
		}).Debugf("ExecveEvent: failed to finalize process exec event")
		// For ProcessExec event we do not fail let's return what we have even if it's not complete
		// The eventmetrics will count further errors
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

func (msg *MsgCgroupEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgCgroupEventUnix RetryInternal() was called")
}

func (msg *MsgCgroupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return fmt.Errorf("Unreachable state: MsgCgroupEventUnix Retry() was called")
}

func (msg *MsgCgroupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	op := ops.CgroupOpCode(msg.CgrpOp)
	st := ops.CgroupState(msg.CgrpData.State).String()
	switch op {
	case ops.MSG_OP_CGROUP_MKDIR, ops.MSG_OP_CGROUP_RMDIR, ops.MSG_OP_CGROUP_RELEASE:
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.event":       op.String(),
			"PID":                msg.PID,
			"NSPID":              msg.NSPID,
			"cgroup.ID":          msg.Cgrpid,
			"cgroup.state":       st,
			"cgroup.hierarchyID": msg.CgrpData.HierarchyId,
			"cgroup.level":       msg.CgrpData.Level,
			"cgroup.path":        cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]),
		}).Debug("Received Cgroup event")
	case ops.MSG_OP_CGROUP_ATTACH_TASK:
		// Here we should get notification when Tetragon migrate itself
		// and discovers cgroups configuration
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.event":       op.String(),
			"PID":                msg.PID,
			"NSPID":              msg.NSPID,
			"cgroup.IDTracker":   msg.CgrpidTracker,
			"cgroup.ID":          msg.Cgrpid,
			"cgroup.state":       st,
			"cgroup.hierarchyID": msg.CgrpData.HierarchyId,
			"cgroup.level":       msg.CgrpData.Level,
			"cgroup.path":        cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]),
		}).Info("Received Cgroup event")
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCgroupMessage: Unhandled Cgroup operation event")
	}
	return nil
}

func (msg *MsgCgroupEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCgroupEvent)
	return &MsgCgroupEventUnix{MsgCgroupEvent: t}
}

type MsgExecveEventUnix struct {
	Unix *processapi.MsgExecveEventUnix
}

func (msg *MsgExecveEventUnix) Notify() bool {
	return true
}

func (msg *MsgExecveEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgExecveEventUnix with missing internal")
}

func (msg *MsgExecveEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	var podInfo *tetragon.Pod

	proc := ev.GetProcess()
	parent := ev.GetParent()

	containerId := proc.Docker
	filename := proc.Binary
	args := proc.Arguments
	nspid := msg.Unix.Process.NSPID

	if option.Config.EnableK8s && containerId != "" {
		cgroupID := msg.Unix.Kube.Cgrpid
		podInfo = process.GetPodInfo(cgroupID, containerId, filename, args, nspid)
		if podInfo == nil {
			eventcache.CacheRetries(eventcache.PodInfo).Inc()
			return eventcache.ErrFailedToGetPodInfo
		}
	}

	// We can assume that event.internal != nil here since it's being set by AddExecEvent
	// earlier in the code path. If this invariant ever changes in the future, we probably
	// want to panic anyway to help us catch the bug faster. So no need to do a nil check
	// here.
	internal.AddPodInfo(podInfo)

	// Check we have a parent with exception for pid 1, note we do this last because we want
	// to ensure the podInfo and process are set before returning any errors.
	if proc.Pid.Value > 1 && parent == nil {
		parentId := proc.ParentExecId
		parent, err := process.Get(parentId)
		if parent == nil {
			return err
		}
		parent.RefInc("parent")
		ev.SetParent(parent.UnsafeGetProcess())
	}

	// As of now pod information has been added, finalize the process event with extra fields
	if err := msg.finalize(ev, internal, eventcache.FROM_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     proc.Pid.GetValue(),
			"event.process.binary":  filename,
			"event.process.exec_id": proc.GetExecId(),
			"event.event_cache":     "yes",
		}).Debugf("ExecveEvent: failed to finalize process exec event")
		// For ProcessExec event we do not fail let's return what we have even if it's not complete
		// The eventmetrics will count further errors
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

	if e := GetProcessExec(msg, true); e != nil {
		res = &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Unix.Msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgExecveEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExecveEventUnix)
	return &MsgExecveEventUnix{Unix: &t}
}

// finalize() is called to finalize Process of the event ExecveEvent
//
// The aim of this function is to finalize events by adding or updating some
// fields without propagating those into the process cache.
// These fields could be related to the specific calling event, example only
// for ProcessExec and not ProcessKprobe.
//
// There are two conditions when we could update the event:
//  1. When the event finalize handler return update set to true, for this a deep copy
//     of the process was made, and the related fields added then the event.Process
//     must be set with ev.SetProcess() to this returned copy.
//  2. The finalize() is called from the event cache retry in this
//     case new information could have been added, so let's do another
//     ev.SetProcess() call to update the process of the event.
func (msg *MsgExecveEventUnix) finalize(ev notify.Event, internal *process.ProcessInternal, cache int) error {
	// This should never happen by this time
	if ev.GetProcess() == nil {
		return process.ErrProcessInfoMissing
	}

	proc, update := internal.UpdateExecOutsideCache(option.Config.EnableProcessCred)
	// Update the event.Process entry:
	// If update == true means we made a new copy of the process, added
	//    new information so let's update the event.
	// If we did reach here from the event cache retries then maybe there is
	//    new information let's update the event again.
	if update || cache == eventcache.FROM_EV_CACHE {
		ev.SetProcess(proc)
	}

	return nil
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

func (msg *MsgCloneEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, process.AddCloneEvent(&msg.MsgCloneEvent)
}

func (msg *MsgCloneEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	if err := process.AddCloneEvent(&msg.MsgCloneEvent); err != nil {
		ec := eventcache.Get()
		if ec != nil {
			ec.Add(nil, nil, msg.MsgCloneEvent.Common.Ktime, msg.MsgCloneEvent.Ktime, msg)
		}
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

	proc, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if proc != nil {
		tetragonProcess = proc.UnsafeGetProcess()
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

	// Per thread tracking rules PID == TID.
	//
	// Exit events should have TID==PID at same time we want to correlate
	// the {TID,PID} of the exit event with the {TID,PID} pair from the exec
	// event. They must match because its how we link the exit event to the
	// exec one.
	//
	// The exit event is constructed when looking up the process by its PID
	// from user space cache, so we endup with the TID that was pushed
	// into the process cache during clone or exec.
	//
	// Add extra logic to WARN on conditions where TID!=PID to aid debugging
	// and catch this unexpected case. Typically this indicates a bug either
	// in BPF or userspace caching logic. When this condition is encountered
	// we warn about it, but for the exit event the TID of the cache process
	// will be re-used.
	//
	// Check must be against event.Info.Tid so we cover all the cases of
	// the tetragonProcess.Pid against BPF.
	if tetragonProcess.Pid.GetValue() != event.Info.Tid {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":           "Exit",
			"event.process.pid":    event.ProcessKey.Pid,
			"event.process.tid":    event.Info.Tid,
			"event.process.binary": tetragonProcess.Binary,
		}).Warn("ExitEvent: process PID and TID mismatch")
		errormetrics.ErrorTotalInc(errormetrics.ProcessPidTidMismatch)
	}

	tetragonEvent := &tetragon.ProcessExit{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Signal:  signal,
		Status:  code,
		Time:    ktime.ToProto(event.Common.Ktime),
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if parent != nil {
		parent.RefDec("parent")
	}
	if proc != nil {
		proc.RefDec("process")
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
		ev.SetParent(parent.UnsafeGetProcess())
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec("parent")
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ParentInfo).Inc()
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		// Use cached version of the process
		ev.SetProcess(internal.UnsafeGetProcess())
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgExitEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse

	msg.RefCntDone = [2]bool{false, false}
	e := GetProcessExit(msg)
	if e != nil {
		res = &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessExit{ProcessExit: e},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
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

func (msg *MsgProcessCleanupEventUnix) RetryInternal(_ notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternal(msg.PID, timestamp)
	var err error

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec("parent")
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ParentInfo).Inc()
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgProcessCleanupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	msg.RefCntDone = [2]bool{false, false}
	if process, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime); process != nil && parent != nil {
		parent.RefDec("parent")
		process.RefDec("process")
	} else {
		if ec := eventcache.Get(); ec != nil {
			ec.Add(nil, nil, msg.Ktime, msg.Ktime, msg)
		}
	}
	return nil
}

func (msg *MsgProcessCleanupEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgProcessCleanupEventUnix{}
}
