// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package exec

import (
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/execcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/process"
	readerexec "github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/node"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	execCache  *execcache.Cache
	eventCache *eventcache.Cache
	enableCred bool
	enableNs   bool
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (e *Grpc) GetProcessExec(
	proc *process.ProcessInternal,
) *tetragon.ProcessExec {
	var tetragonParent *tetragon.Process

	tetragonProcess := proc.UnsafeGetProcess()

	parentId := tetragonProcess.ParentExecId
	processId := tetragonProcess.ExecId

	parent, err := process.Get(parentId)
	if err != nil {
		metrics.ErrorCount.WithLabelValues(string(metrics.ExecMissingParent)).Inc()
		metrics.ExecMissingParentErrors.WithLabelValues(parentId).Inc()
		logger.GetLogger().WithField("processId", processId).WithField("parentId", parentId).Debug("Process missing parent")
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(e.enableCred, e.enableNs); err != nil {
		logger.GetLogger().WithError(err).WithField("processId", processId).WithField("parentId", parentId).Debugf("Failed to annotate process with capabilities and namespaces info")
	}
	if parent != nil {
		tetragonParent = parent.GetProcessCopy()
	}

	// If this is not a clone we need to decrement parent refcnt because
	// the parent has been replaced and will not get its own exit event.
	// The new process will hold needed refcnts until it is destroyed.
	if strings.Contains(tetragonProcess.Flags, "clone") == false &&
		strings.Contains(tetragonProcess.Flags, "procFS") == false &&
		parent != nil {
		parent.RefDec()
	}

	return &tetragon.ProcessExec{
		Process: tetragonProcess,
		Parent:  tetragonParent,
	}
}

func (e *Grpc) HandleExecveMessage(msg *tetragonAPI.MsgExecveEventUnix) *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXECVE:
		proc := process.AddExecEvent(msg)
		procEvent := e.GetProcessExec(proc)
		if e.eventCache.Needed(procEvent.Process) {
			e.execCache.Add(proc, procEvent, ktime.ToProto(msg.Common.Ktime), msg)
		} else {
			procEvent.Process = proc.GetProcessCopy()
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

// GetProcessExit returns Exit protobuf message for a given process.
func (e *Grpc) GetProcessExit(event *tetragonAPI.MsgExitEventUnix) *tetragon.ProcessExit {
	var tetragonProcess, tetragonParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		process.RefDec()
		tetragonProcess = process.UnsafeGetProcess()
	} else {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		parent.RefDec()
		tetragonParent = parent.GetProcessCopy()
	}

	code := event.Info.Code >> 8
	signal := readerexec.Signal(event.Info.Code & 0xFF)

	tetragonEvent := &tetragon.ProcessExit{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Signal:  signal,
		Status:  code,
	}
	if e.eventCache.Needed(tetragonProcess) {
		e.eventCache.Add(process, tetragonEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

func (e *Grpc) HandleExitMessage(msg *tetragonAPI.MsgExitEventUnix) *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXIT:
		e := e.GetProcessExit(msg)
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

func New(exec *execcache.Cache, event *eventcache.Cache, cred, ns bool) *Grpc {
	return &Grpc{
		execCache:  exec,
		eventCache: event,
		enableCred: cred,
		enableNs:   ns,
	}
}
