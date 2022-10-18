// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
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
)

var (
	nodeName = node.GetNodeNameForExport()
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
		parent.RefInc()
		tetragonParent = parent.GetProcessCopy()
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
		logger.GetLogger().WithError(err).WithField("processId", processId).WithField("parentId", parentId).Debugf("Failed to annotate process with capabilities and namespaces info")
	}

	tetragonProcess = proc.GetProcessCopy()
	tetragonEvent := &tetragon.ProcessExec{
		Process: tetragonProcess,
		Parent:  tetragonParent,
	}

	if useCache {
		act := &notify.CacheActions{
			NeedProcess:    false,
			NeedProcessPod: eventcache.NeededPod(tetragonProcess),
			NeedParent:     event.Process.PID > 1 && eventcache.NeededProcess(tetragonParent),
			NeedParentPod:  event.Process.PID > 1 && eventcache.NeededPod(tetragonParent),
		}
		if ec := eventcache.Get(); ec != nil && ec.Needed(act) {
			ec.Add(tetragonEvent, event.Process.PID, event.Process.Ktime, event.Common.Ktime, event, act)
			return nil
		}
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
				"cgroup.event":       op.String(),
				"PID":                msg.PID,
				"NSPID":              msg.NSPID,
				"cgroup.IDTracker":   msg.CgrpidTracker,
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

var _ notify.CacheRetry = (*MsgExecveEventUnix)(nil)

func (msg *MsgExecveEventUnix) Notify() bool {
	// should be done only once
	if cleanupEvent := msg.getCleanupEvent(); cleanupEvent != nil {
		// Retry() is going to be executed in the cache loop handling function, but
		// HandleMessage may enqueue something in the cache channel. To avoid a deadlock,
		// execute the cleanup message handling in a separate goroutine.
		go cleanupEvent.HandleMessage()
	}
	return true
}

// Exec events will always have a process entry in the cache. In this case we
// should check (and add) podInfo if needed. The generic Retry waits for this
// event to set the correct pod info.
func (msg *MsgExecveEventUnix) Retry(ev notify.Event, ca *notify.CacheActions, pid uint32, timestamp uint64) error {
	internal, parent := process.GetParentProcessInternal(pid, timestamp)
	var err error

	if ca.NeedProcess {
		return fmt.Errorf("event MsgExecveEventUnix cannot miss process info")
	}

	if !ca.NeedProcess && ca.NeedProcessPod {
		if internal != nil {
			proc := internal.UnsafeGetProcess()
			if option.Config.EnableK8s && proc.Docker != "" {
				if podInfo, _ := process.GetPodInfo(proc.Docker, proc.Binary, proc.Arguments, msg.Process.NSPID); podInfo == nil {
					errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
					err = eventcache.ErrFailedToGetPodInfo
				} else {
					internal.AddPodInfo(podInfo)
					ev.SetProcess(internal.GetProcessCopy())
					ca.NeedProcessPod = false
				}
			} else {
				ca.NeedProcessPod = false
			}
		} else {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
			err = eventcache.ErrFailedToGetProcessInfo
		}
	}

	if ca.NeedParent {
		if parent == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
			err = eventcache.ErrFailedToGetParentInfo
		} else {
			parent.RefInc()
			ev.SetParent(parent.GetProcessCopy())
			ca.NeedParent = false
		}
	}

	if !ca.NeedParent && ca.NeedParentPod {
		if parent != nil { // we report errors for that in the previous if no need to do that again
			if option.Config.EnableK8s {
				if p := parent.UnsafeGetProcess(); p.Docker != "" {
					if p.Pod == nil {
						errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
						err = eventcache.ErrFailedToGetPodInfo
					} else {
						ev.SetParent(parent.GetProcessCopy())
						ca.NeedParentPod = false
					}
				}
			}
		}
	}

	return err
}

func (msg *MsgExecveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	if e := GetProcessExec(msg, true); e != nil {
		return &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
	}
	return nil
}

func (msg *MsgExecveEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExecveEventUnix)
	return &MsgExecveEventUnix{MsgExecveEventUnix: t}
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

var _ notify.CacheRetry = (*MsgCloneEventUnix)(nil)

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

// Clone event does not result in a user event. This is a special case as we
// don't need to find a process. We only need the parent and the process is
// actually a copy of the parent (with small updates). This is also differs
// from the generic Retry as it also sets pod info in a similar way to exec
// events.
func (msg *MsgCloneEventUnix) Retry(ev notify.Event, ca *notify.CacheActions, pid uint32, timestamp uint64) error {
	var err error

	if ca.NeedProcess {
		if internal, _ := process.AddCloneEvent(&msg.MsgCloneEvent); internal == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
			err = eventcache.ErrFailedToGetProcessInfo
		} else {
			ca.NeedProcess = false
		}
	}

	if !ca.NeedProcess && ca.NeedProcessPod {
		if internal, _ := process.GetParentProcessInternal(pid, timestamp); internal != nil {
			proc := internal.UnsafeGetProcess()
			if option.Config.EnableK8s && proc.Docker != "" {
				if podInfo, _ := process.GetPodInfo(proc.Docker, proc.Binary, proc.Arguments, msg.NSPID); podInfo == nil {
					errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
					err = eventcache.ErrFailedToGetPodInfo
				} else {
					internal.AddPodInfo(podInfo)
					ca.NeedProcessPod = false
				}
			} else {
				ca.NeedProcessPod = false
			}
		} else {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
			err = eventcache.ErrFailedToGetProcessInfo
		}
	}

	return err
}

func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	internal, err := process.AddCloneEvent(&msg.MsgCloneEvent)
	if internal == nil || err != nil {
		act := &notify.CacheActions{
			NeedProcess:    internal == nil,
			NeedProcessPod: internal != nil && eventcache.NeededPod(internal.UnsafeGetProcess()),
			NeedParent:     false,
			NeedParentPod:  false,
		}

		if ec := eventcache.Get(); ec != nil && ec.Needed(act) {
			ec.Add(nil, msg.PID, msg.Ktime, 0, msg, act)
			return nil
		}
	}
	return nil
}

func (msg *MsgCloneEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCloneEvent)
	return &MsgCloneEventUnix{MsgCloneEvent: t}
}

type MsgExitEventUnix struct {
	processapi.MsgExitEvent
}

func (msg *MsgExitEventUnix) Notify() bool {
	return true
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	code := msg.Info.Code >> 8
	signal := readerexec.Signal(msg.Info.Code & 0xFF)

	tetragonEvent := &tetragon.ProcessExit{
		Signal: signal,
		Status: code,
	}

	return eventcache.AddProcessParentRefDec(tetragonEvent, msg, msg.ProcessKey.Pid, msg.ProcessKey.Ktime, msg.Common.Ktime)
}

func (msg *MsgExitEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExitEvent)
	return &MsgExitEventUnix{MsgExitEvent: t}
}

type MsgProcessCleanupEventUnix struct {
	PID   uint32
	Ktime uint64
}

var _ notify.CacheRetry = (*MsgProcessCleanupEventUnix)(nil)

func (msg *MsgProcessCleanupEventUnix) Notify() bool {
	return false
}

// Cleanup events does not result in a user event. In this case we need a
// custom Retry function as we only need to decrease the refcnt in both the
// process and parent.
func (msg *MsgProcessCleanupEventUnix) Retry(ev notify.Event, ca *notify.CacheActions, pid uint32, timestamp uint64) error {
	proc, parent := process.GetParentProcessInternal(pid, timestamp)
	var err error

	if ca.NeedProcess {
		if proc == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
			err = eventcache.ErrFailedToGetProcessInfo
		} else {
			proc.RefDec()
			ca.NeedProcess = false
		}
	}

	if ca.NeedParent {
		if parent == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
			err = eventcache.ErrFailedToGetParentInfo
		} else {
			parent.RefDec()
			ca.NeedParent = false
		}
	}

	return err
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	process, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime)
	if process != nil && parent != nil {
		process.RefDec()
		parent.RefDec()
	} else {
		act := &notify.CacheActions{
			NeedProcess:    true,
			NeedProcessPod: false,
			NeedParent:     true,
			NeedParentPod:  false,
		}
		if ec := eventcache.Get(); ec != nil && ec.Needed(act) {
			ec.Add(nil, msg.PID, msg.Ktime, 0, msg, act)
			return nil
		}
	}
	return nil
}

func (msg *MsgProcessCleanupEventUnix) Cast(o interface{}) notify.Message {
	return &MsgProcessCleanupEventUnix{}
}
