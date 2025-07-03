// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"errors"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	readerexec "github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ProcessRefCnt = iota
	ParentRefCnt
	AncestorsRefCnt
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
	var tetragonAncestors []*tetragon.Process
	var ancestors []*process.ProcessInternal

	proc := process.AddExecEvent(event.Unix)
	tetragonProcess := proc.UnsafeGetProcess()

	parentId := tetragonProcess.ParentExecId
	processId := tetragonProcess.ExecId

	parent, err := process.Get(parentId)
	if err == nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	// Set the ancestors only if --enable-ancestors flag includes 'base'.
	if option.Config.EnableProcessAncestors && proc.NeededAncestors() {
		// We don't care about an error here, because later we call ec.NeededAncestors,
		// that will determine if we were successful in collecting all ancestors and,
		// if we were not, the event will be added to the event cache for reprocessing.
		// Even if we were not able to collect all ancestors, we will still export what
		// we were able to collect in the event.
		ancestors, _ = process.GetAncestorProcessesInternal(tetragonProcess.ParentExecId)
		for _, ancestor := range ancestors {
			tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
		}
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
		logger.GetLogger().Debug("Failed to annotate process with capabilities and namespaces info",
			"processId", processId, "parentId", parentId, logfields.Error, err)
	}

	tetragonEvent := &tetragon.ProcessExec{
		Process:   tetragonProcess,
		Parent:    tetragonParent,
		Ancestors: tetragonAncestors,
	}

	if option.Config.EnableProcessEnvironmentVariables {
		tetragonEvent.EnvironmentVariables = proc.GetEnvironmentVariables()
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if useCache {
		if ec := eventcache.Get(); ec != nil &&
			(ec.Needed(tetragonProcess) ||
				(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent)) ||
				(option.Config.EnableProcessAncestors && ec.NeededAncestors(parent, ancestors))) {
			ec.Add(proc, tetragonEvent, event.Unix.Msg.Common.Ktime, event.Unix.Process.Ktime, event)
			return nil
		}
	}

	if option.Config.EnableProcessAncestors {
		for _, ancestor := range ancestors {
			ancestor.RefInc("ancestor")
		}
	}
	if parent != nil {
		parent.RefInc("parent")
	}

	// Finalize the process event with extra fields
	if err := event.finalize(tetragonEvent, proc, eventcache.NO_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().Debug("ExecveEvent: failed to finalize process exec event",
			"event.name", "Execve",
			"event.process.pid", tetragonProcess.GetPid().GetValue(),
			"event.process.binary", tetragonProcess.Binary,
			"event.process.exec_id", processId,
			"event.event_cache", "no")
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
	return nil, errors.New("unreachable state: MsgCgroupEventUnix RetryInternal() was called")
}

func (msg *MsgCgroupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return errors.New("unreachable state: MsgCgroupEventUnix Retry() was called")
}

func (msg *MsgCgroupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	op := ops.CgroupOpCode(msg.CgrpOp)
	st := ops.CgroupState(msg.CgrpData.State).String()
	switch op {
	case ops.MSG_OP_CGROUP_MKDIR, ops.MSG_OP_CGROUP_RMDIR, ops.MSG_OP_CGROUP_RELEASE:
		logger.GetLogger().Debug("Received Cgroup event",
			"cgroup.event", op.String(),
			"PID", msg.PID,
			"NSPID", msg.NSPID,
			"cgroup.ID", msg.Cgrpid,
			"cgroup.state", st,
			"cgroup.hierarchyID", msg.CgrpData.HierarchyId,
			"cgroup.level", msg.CgrpData.Level,
			"cgroup.path", cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]))
	case ops.MSG_OP_CGROUP_ATTACH_TASK:
		// Here we should get notification when Tetragon migrate itself
		// and discovers cgroups configuration
		logger.GetLogger().Info("Received Cgroup event",
			"cgroup.event", op.String(),
			"PID", msg.PID,
			"NSPID", msg.NSPID,
			"cgroup.IDTracker", msg.CgrpidTracker,
			"cgroup.ID", msg.Cgrpid,
			"cgroup.state", st,
			"cgroup.hierarchyID", msg.CgrpData.HierarchyId,
			"cgroup.level", msg.CgrpData.Level,
			"cgroup.path", cgroups.CgroupNameFromCStr(msg.Path[:processapi.CGROUP_PATH_LENGTH]))
	default:
		logger.GetLogger().Warn("HandleCgroupMessage: Unhandled Cgroup operation event", "message", msg)
	}
	return nil
}

func (msg *MsgCgroupEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCgroupEvent)
	return &MsgCgroupEventUnix{MsgCgroupEvent: t}
}

type MsgExecveEventUnix struct {
	Unix       *processapi.MsgExecveEventUnix
	RefCntDone [3]bool
}

func (msg *MsgExecveEventUnix) Notify() bool {
	return true
}

func (msg *MsgExecveEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, errors.New("unreachable state: MsgExecveEventUnix with missing internal")
}

func (msg *MsgExecveEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	var podInfo *tetragon.Pod

	tetragonProcess := ev.GetProcess()
	containerId := tetragonProcess.Docker
	filename := tetragonProcess.Binary
	args := tetragonProcess.Arguments
	nspid := msg.Unix.Process.NSPID

	if option.Config.EnableK8s && containerId != "" {
		podInfo = process.GetPodInfo(containerId, filename, args, nspid)
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
	if tetragonProcess.Pid.Value > 1 && !msg.RefCntDone[ParentRefCnt] {
		parentId := tetragonProcess.ParentExecId
		parent, err := process.Get(parentId)
		if parent == nil {
			eventcache.CacheRetries(eventcache.ParentInfo).Inc()
			return err
		}
		parent.RefInc("parent")
		ev.SetParent(parent.UnsafeGetProcess())
		msg.RefCntDone[ParentRefCnt] = true
	}

	// Check if we have ancestors with exception for pid 1 and pid 2. Note that we pass
	// tetragonProcess.ParentExecId to GetAncestorProcessesInternal function instead of
	// tetragonProcess.ExecId, because function GetAncestorProcessesInternal returns all
	// ancestors of the given process, including the immediate parent. So in order for us
	// to collect ancestors beyond immediate parent, we need to pass immediate parent to
	// GetAncestorProcessesInternal.
	if option.Config.EnableProcessAncestors && internal.NeededAncestors() && !msg.RefCntDone[AncestorsRefCnt] {
		if ancestors, err := process.GetAncestorProcessesInternal(tetragonProcess.ParentExecId); err == nil {
			var tetragonAncestors []*tetragon.Process
			for _, ancestor := range ancestors {
				tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
				ancestor.RefInc("ancestor")
			}
			ev.SetAncestors(tetragonAncestors)
			msg.RefCntDone[AncestorsRefCnt] = true
		} else {
			eventcache.CacheRetries(eventcache.AncestorsInfo).Inc()
			return eventcache.ErrFailedToGetAncestorsInfo
		}
	}

	// As of now pod information has been added, finalize the process event with extra fields
	if err := msg.finalize(ev, internal, eventcache.FROM_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().Debug("ExecveEvent: failed to finalize process exec event",
			"event.name", "Execve",
			"event.process.pid", tetragonProcess.Pid.GetValue(),
			"event.process.binary", filename,
			"event.process.exec_id", tetragonProcess.GetExecId(),
			"event.event_cache", "yes")
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

	msg.RefCntDone = [3]bool{true, false, false}
	if e := GetProcessExec(msg, true); e != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
			Time:  ktime.ToProto(msg.Unix.Msg.Common.Ktime),
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
	return process.AddCloneEvent(&msg.MsgCloneEvent)
}

func (msg *MsgCloneEventUnix) Retry(internal *process.ProcessInternal, _ notify.Event) error {
	tetragonProcess := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && tetragonProcess.Docker != "" && tetragonProcess.Pod == nil {
		podInfo := process.GetPodInfo(tetragonProcess.Docker, tetragonProcess.Binary, tetragonProcess.Arguments, msg.NSPID)
		if podInfo == nil {
			eventcache.CacheRetries(eventcache.PodInfo).Inc()
			return eventcache.ErrFailedToGetPodInfo
		}
		internal.AddPodInfo(podInfo)
	}

	if option.Config.EnableProcessAncestors && internal.NeededAncestors() {
		if ancestors, err := process.GetAncestorProcessesInternal(tetragonProcess.ParentExecId); err == nil {
			for _, ancestor := range ancestors {
				ancestor.RefInc("ancestor")
			}
		} else {
			eventcache.CacheRetries(eventcache.AncestorsInfo).Inc()
			return eventcache.ErrFailedToGetAncestorsInfo
		}
	}

	return nil
}

func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var ancestors []*process.ProcessInternal

	proc, _ := process.AddCloneEvent(&msg.MsgCloneEvent)
	if option.Config.EnableProcessAncestors && proc.NeededAncestors() {
		ancestors, _ = process.GetAncestorProcessesInternal(proc.UnsafeGetProcess().ParentExecId)
	}

	if ec := eventcache.Get(); ec != nil {
		if proc == nil {
			// adding to the cache due to missing parent
			ec.Add(nil, nil, msg.Common.Ktime, msg.Ktime, msg)
			return nil
		}

		parent, _ := process.Get(proc.UnsafeGetProcess().ParentExecId)

		if ec.Needed(proc.UnsafeGetProcess()) ||
			option.Config.EnableProcessAncestors && ec.NeededAncestors(parent, ancestors) {
			// adding to the cache due to missing pod info or ancestors
			ec.Add(proc, nil, msg.Common.Ktime, msg.Ktime, msg)
			return nil
		}
	}

	if option.Config.EnableProcessAncestors {
		for _, ancestor := range ancestors {
			ancestor.RefInc("ancestor")
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
	var tetragonAncestors []*tetragon.Process
	var ancestors []*process.ProcessInternal

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

	// Set the ancestors only if --enable-ancestors flag includes 'base'.
	if option.Config.EnableProcessAncestors && proc.NeededAncestors() {
		// We don't care about an error here, because later we call ec.NeededAncestors,
		// that will determine if we were successful in collecting all ancestors and,
		// if we were not, the event will be added to the event cache for reprocessing.
		// Even if we were not able to collect all ancestors, we will still export what
		// we were able to collect in the event.
		ancestors, _ = process.GetAncestorProcessesInternal(tetragonProcess.ParentExecId)
		for _, ancestor := range ancestors {
			tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
		}
	}

	code := event.Info.Code >> 8
	signal := readerexec.Signal(event.Info.Code & 0xFF)

	if event.Info.Code&0x80 != 0 {
		// Core dumped
		signal = readerexec.Signal(event.Info.Code & 0x7F)
	}

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
		logger.GetLogger().Warn("ExitEvent: process PID and TID mismatch",
			"event.name", "Exit",
			"event.process.pid", event.ProcessKey.Pid,
			"event.process.tid", event.Info.Tid,
			"event.process.binary", tetragonProcess.Binary)
		errormetrics.ErrorTotalInc(errormetrics.ProcessPidTidMismatch)
	}

	tetragonEvent := &tetragon.ProcessExit{
		Process:   tetragonProcess,
		Parent:    tetragonParent,
		Ancestors: tetragonAncestors,
		Signal:    signal,
		Status:    code,
		Time:      ktime.ToProto(event.Common.Ktime),
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent)) ||
			(option.Config.EnableProcessAncestors && ec.NeededAncestors(parent, ancestors))) {
		ec.Add(nil, tetragonEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}

	if option.Config.EnableProcessAncestors {
		for _, ancestor := range ancestors {
			ancestor.RefDec("ancestor")
		}
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
	processapi.MsgExitEvent
	RefCntDone [3]bool
}

func (msg *MsgExitEventUnix) Notify() bool {
	return true
}

func (msg *MsgExitEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	proc, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, timestamp)
	var err error

	if option.Config.EnableProcessAncestors && proc.NeededAncestors() && !msg.RefCntDone[AncestorsRefCnt] {
		if ancestors, perr := process.GetAncestorProcessesInternal(proc.UnsafeGetProcess().ParentExecId); perr == nil {
			var tetragonAncestors []*tetragon.Process
			for _, ancestor := range ancestors {
				tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
				ancestor.RefDec("ancestor")
			}
			ev.SetAncestors(tetragonAncestors)
			msg.RefCntDone[AncestorsRefCnt] = true
		} else {
			eventcache.CacheRetries(eventcache.AncestorsInfo).Inc()
			err = eventcache.ErrFailedToGetAncestorsInfo
		}
	}

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

	if proc != nil {
		// Use cached version of the process
		ev.SetProcess(proc.UnsafeGetProcess())
		if !msg.RefCntDone[ProcessRefCnt] {
			proc.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return proc, err
	}
	return nil, err
}

func (msg *MsgExitEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse

	msg.RefCntDone = [3]bool{false, false, false}
	e := GetProcessExit(msg)
	if e != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: e},
			Time:  ktime.ToProto(msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgExitEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExitEvent)
	return &MsgExitEventUnix{MsgExitEvent: t}
}

type MsgProcessCleanupEventUnix struct {
	PID        uint32
	Ktime      uint64
	RefCntDone [3]bool
}

func (msg *MsgProcessCleanupEventUnix) Notify() bool {
	return false
}

func (msg *MsgProcessCleanupEventUnix) RetryInternal(_ notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	proc, parent := process.GetParentProcessInternal(msg.PID, timestamp)
	var err error

	if option.Config.EnableProcessAncestors && proc.NeededAncestors() && !msg.RefCntDone[AncestorsRefCnt] {
		if ancestors, perr := process.GetAncestorProcessesInternal(proc.UnsafeGetProcess().ParentExecId); perr == nil {
			for _, ancestor := range ancestors {
				ancestor.RefDec("ancestor")
			}
			msg.RefCntDone[AncestorsRefCnt] = true
		} else {
			eventcache.CacheRetries(eventcache.AncestorsInfo).Inc()
			err = eventcache.ErrFailedToGetAncestorsInfo
		}
	}

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec("parent")
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ParentInfo).Inc()
		err = eventcache.ErrFailedToGetParentInfo
	}

	if proc != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			proc.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return proc, err
	}
	return nil, err
}

func (msg *MsgProcessCleanupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var ancestors []*process.ProcessInternal

	msg.RefCntDone = [3]bool{false, false, false}
	proc, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime)
	if option.Config.EnableProcessAncestors && proc.NeededAncestors() {
		ancestors, _ = process.GetAncestorProcessesInternal(proc.UnsafeGetProcess().ParentExecId)
	}

	if ec := eventcache.Get(); ec != nil &&
		(proc == nil ||
			parent == nil ||
			option.Config.EnableProcessAncestors && ec.NeededAncestors(parent, ancestors)) {
		ec.Add(nil, nil, msg.Ktime, msg.Ktime, msg)
		return nil
	}

	if option.Config.EnableProcessAncestors {
		for _, ancestor := range ancestors {
			ancestor.RefDec("ancestor")
		}
	}
	if parent != nil {
		parent.RefDec("parent")
	}
	if proc != nil {
		proc.RefDec("process")
	}
	return nil
}

func (msg *MsgProcessCleanupEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgProcessCleanupEventUnix{}
}
