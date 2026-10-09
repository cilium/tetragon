// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// MsgJavaEvent is the observer-to-gRPC representation of a Java method
// entry received from the jvmti agent.
type MsgJavaEvent struct {
	// Pid of the JVM, as seen by tetragon (from the agent socket peer
	// credentials, not reported by the JVM itself).
	Pid uint32
	Tid uint32
	// Ktime of the method entry (CLOCK_MONOTONIC, same as bpf ktime).
	Ktime      uint64
	MethodID   uint64
	ClassName  string
	MethodName string
	Descriptor string
	PolicyName string
	Message    string
	Tags       []string
}

func (msg *MsgJavaEvent) Notify() bool {
	return true
}

func (msg *MsgJavaEvent) Cast(o any) notify.Message {
	return new(o.(MsgJavaEvent))
}

func (msg *MsgJavaEvent) PolicyInfo() tracingpolicy.PolicyInfo {
	return tracingpolicy.PolicyInfo{
		Name: msg.PolicyName,
		Hook: "java:" + msg.ClassName + "." + msg.MethodName,
	}
}

func (msg *MsgJavaEvent) RetryInternal(_ notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternalByPID(msg.Pid, timestamp)
	if internal == nil {
		return nil, eventcache.ErrFailedToGetProcessInfo
	}
	if parent == nil {
		return nil, eventcache.ErrFailedToGetParentInfo
	}
	return internal, nil
}

func (msg *MsgJavaEvent) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Tid)
}

func GetProcessJava(msg *MsgJavaEvent) *tetragon.ProcessJava {
	var ancestors []*process.ProcessInternal
	var tetragonAncestors []*tetragon.Process
	var tetragonProcess, tetragonParent *tetragon.Process

	proc, parent := process.GetParentProcessInternalByPID(msg.Pid, msg.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.Pid},
			StartTime: ktime.ToProto(msg.Ktime),
			Flags:     "unknown",
		}
	} else {
		tetragonProcess = proc.UnsafeGetProcess()
		if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
			logger.GetLogger().Debug("Failed to annotate Java process with capabilities and namespaces info",
				"processId", tetragonProcess.Pid, logfields.Error, err)
		}
		if parent != nil {
			tetragonParent = parent.UnsafeGetProcess()
		}
	}

	// Set the ancestors only if --enable-ancestors flag includes 'java'.
	if option.Config.EnableProcessJavaAncestors && proc != nil && proc.NeededAncestors() {
		ancestors, _ = process.GetAncestorProcessesInternal(tetragonProcess.ParentExecId)
		for _, ancestor := range ancestors {
			tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
		}
	}

	tetragonEvent := &tetragon.ProcessJava{
		Process:     tetragonProcess,
		Parent:      tetragonParent,
		Ancestors:   tetragonAncestors,
		MethodId:    msg.MethodID,
		ClassName:   msg.ClassName,
		MethodName:  msg.MethodName,
		Descriptor_: msg.Descriptor,
		PolicyName:  msg.PolicyName,
		Message:     msg.Message,
		Tags:        msg.Tags,
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil && !isUnknown(tetragonProcess) &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent)) ||
			(option.Config.EnableProcessJavaAncestors && ec.NeededAncestors(parent, ancestors))) {
		ec.Add(nil, tetragonEvent, msg.Ktime, msg.Ktime, msg)
		return nil
	}

	if proc != nil {
		// Report the per thread fields, so take a copy of the thread
		// leader from the cache then update the per thread fields.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &msg.Tid)
	}
	return tetragonEvent
}

func (msg *MsgJavaEvent) HandleMessage() *tetragon.GetEventsResponse {
	k := GetProcessJava(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessJava{ProcessJava: k},
		Time:  ktime.ToProto(msg.Ktime),
	}
}
