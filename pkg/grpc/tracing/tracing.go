// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/bpf"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/reader/path"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

func kprobeAction(act uint64) tetragon.KprobeAction {
	switch act {
	case tracingapi.ActionPost:
		return tetragon.KprobeAction_KPROBE_ACTION_POST
	case tracingapi.ActionFollowFd:
		return tetragon.KprobeAction_KPROBE_ACTION_FOLLOWFD
	case tracingapi.ActionSigKill:
		return tetragon.KprobeAction_KPROBE_ACTION_SIGKILL
	case tracingapi.ActionUnfollowFd:
		return tetragon.KprobeAction_KPROBE_ACTION_UNFOLLOWFD
	case tracingapi.ActionOverride:
		return tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE
	case tracingapi.ActionCopyFd:
		return tetragon.KprobeAction_KPROBE_ACTION_COPYFD
	case tracingapi.ActionGetUrl:
		return tetragon.KprobeAction_KPROBE_ACTION_GETURL
	case tracingapi.ActionLookupDns:
		return tetragon.KprobeAction_KPROBE_ACTION_DNSLOOKUP
	case tracingapi.ActionNoPost:
		return tetragon.KprobeAction_KPROBE_ACTION_NOPOST
	case tracingapi.ActionSignal:
		return tetragon.KprobeAction_KPROBE_ACTION_SIGNAL
	default:
		return tetragon.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

func GetProcessKprobe(event *MsgGenericKprobeUnix) *tetragon.ProcessKprobe {
	var tetragonParent, tetragonProcess *tetragon.Process
	var tetragonArgs []*tetragon.KprobeArgument
	var tetragonReturnArg *tetragon.KprobeArgument

	proc, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = proc.UnsafeGetProcess()
		if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
			logger.GetLogger().WithError(err).WithField("processId", tetragonProcess.Pid).Debugf("Failed to annotate process with capabilities and namespaces info")
		}
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	for _, arg := range event.Args {
		a := &tetragon.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &tetragon.KprobeArgument_IntArg{IntArg: e.Value}
			a.Label = e.Label
		case api.MsgGenericKprobeArgUInt:
			a.Arg = &tetragon.KprobeArgument_UintArg{UintArg: e.Value}
			a.Label = e.Label
		case api.MsgGenericKprobeArgSize:
			a.Arg = &tetragon.KprobeArgument_SizeArg{SizeArg: e.Value}
			a.Label = e.Label
		case api.MsgGenericKprobeArgString:
			a.Arg = &tetragon.KprobeArgument_StringArg{StringArg: e.Value}
			a.Label = e.Label
		case api.MsgGenericKprobeArgSock:
			sockArg := &tetragon.KprobeSock{
				Cookie:   e.Sockaddr,
				Family:   network.InetFamily(e.Family),
				Type:     network.InetType(e.Type),
				Protocol: network.InetProtocol(e.Protocol),
				Mark:     e.Mark,
				Priority: e.Priority,
				Saddr:    e.Saddr,
				Daddr:    e.Daddr,
				Sport:    e.Sport,
				Dport:    e.Dport,
			}
			a.Arg = &tetragon.KprobeArgument_SockArg{SockArg: sockArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgSkb:
			skbArg := &tetragon.KprobeSkb{
				Hash:        e.Hash,
				Len:         e.Len,
				Priority:    e.Priority,
				Mark:        e.Mark,
				Saddr:       e.Saddr,
				Daddr:       e.Daddr,
				Sport:       e.Sport,
				Dport:       e.Dport,
				Proto:       e.Proto,
				Protocol:    network.InetProtocol(uint16(e.Proto)),
				SecPathLen:  e.SecPathLen,
				SecPathOlen: e.SecPathOLen,
			}
			a.Arg = &tetragon.KprobeArgument_SkbArg{SkbArg: skbArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgCred:
			capsArg := &tetragon.KprobeCred{
				Permitted:   caps.GetCapabilitiesTypes(e.Permitted),
				Effective:   caps.GetCapabilitiesTypes(e.Effective),
				Inheritable: caps.GetCapabilitiesTypes(e.Inheritable),
			}
			a.Arg = &tetragon.KprobeArgument_CredArg{CredArg: capsArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgBytes:
			if e.OrigSize > uint64(len(e.Value)) {
				a.Arg = &tetragon.KprobeArgument_TruncatedBytesArg{
					TruncatedBytesArg: &tetragon.KprobeTruncatedBytes{
						OrigSize: e.OrigSize,
						BytesArg: e.Value,
					},
				}
			} else {
				a.Arg = &tetragon.KprobeArgument_BytesArg{BytesArg: e.Value}
			}
			a.Label = e.Label
		case api.MsgGenericKprobeArgFile:
			fileArg := &tetragon.KprobeFile{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_FileArg{FileArg: fileArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgPath:
			pathArg := &tetragon.KprobePath{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_PathArg{PathArg: pathArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgBpfAttr:
			bpfAttrArg := &tetragon.KprobeBpfAttr{
				ProgType: bpf.GetProgType(e.ProgType),
				InsnCnt:  e.InsnCnt,
				ProgName: e.ProgName,
			}
			a.Arg = &tetragon.KprobeArgument_BpfAttrArg{BpfAttrArg: bpfAttrArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgPerfEvent:
			perfEventArg := &tetragon.KprobePerfEvent{
				KprobeFunc:  e.KprobeFunc,
				Type:        bpf.GetPerfEventType(e.Type),
				Config:      e.Config,
				ProbeOffset: e.ProbeOffset,
			}
			a.Arg = &tetragon.KprobeArgument_PerfEventArg{PerfEventArg: perfEventArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgBpfMap:
			bpfMapArg := &tetragon.KprobeBpfMap{
				MapType:    bpf.GetBpfMapType(e.MapType),
				KeySize:    e.KeySize,
				ValueSize:  e.ValueSize,
				MaxEntries: e.MaxEntries,
				MapName:    e.MapName,
			}
			a.Arg = &tetragon.KprobeArgument_BpfMapArg{BpfMapArg: bpfMapArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgUserNamespace:
			nsArg := &tetragon.UserNamespace{
				Level: &wrapperspb.Int32Value{Value: e.Level},
				Uid:   &wrapperspb.UInt32Value{Value: e.Uid},
				Gid:   &wrapperspb.UInt32Value{Value: e.Gid},
				Ns: &tetragon.Namespace{
					Inum: e.NsInum,
				},
			}
			if e.Level == 0 {
				nsArg.Ns.IsHost = true
			}
			a.Arg = &tetragon.KprobeArgument_UserNsArg{UserNsArg: nsArg}
			a.Label = e.Label
		case api.MsgGenericKprobeArgCapability:
			cArg := &tetragon.KprobeCapability{
				Value: &wrapperspb.Int32Value{Value: e.Value},
			}
			cArg.Name, _ = caps.GetCapability(e.Value)
			a.Arg = &tetragon.KprobeArgument_CapabilityArg{CapabilityArg: cArg}
			a.Label = e.Label
		default:
			logger.GetLogger().WithField("arg", e).Warnf("unexpected type: %T", e)
		}
		if arg.IsReturnArg() {
			tetragonReturnArg = a
		} else {
			tetragonArgs = append(tetragonArgs, a)
		}
	}

	tetragonEvent := &tetragon.ProcessKprobe{
		Process:      tetragonProcess,
		Parent:       tetragonParent,
		FunctionName: event.FuncName,
		Args:         tetragonArgs,
		Return:       tetragonReturnArg,
		Action:       kprobeAction(event.Action),
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}

	if proc != nil {
		tetragonEvent.Process = proc.GetProcessCopy()
		// Use the bpf recorded TID to update the event
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Tid)
	}
	if parent != nil {
		tetragonEvent.Parent = tetragonParent
	}

	return tetragonEvent
}

type MsgGenericTracepointUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Id         int64
	Tid        uint32
	Subsys     string
	Event      string
	Args       []tracingapi.MsgGenericTracepointArg
	PolicyName string
}

func (msg *MsgGenericTracepointUnix) Notify() bool {
	return true
}

func (msg *MsgGenericTracepointUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.ProcessKey.Pid, &msg.Tid, timestamp)
}

func (msg *MsgGenericTracepointUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Tid)
}

func (msg *MsgGenericTracepointUnix) HandleMessage() *tetragon.GetEventsResponse {
	var tetragonParent, tetragonProcess *tetragon.Process

	proc, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = proc.UnsafeGetProcess()
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	var tetragonArgs []*tetragon.KprobeArgument
	for _, arg := range msg.Args {
		switch v := arg.(type) {
		case uint64:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SizeArg{
				SizeArg: v,
			}})
		case int64:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_LongArg{
				LongArg: v,
			}})
		case uint32:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_UintArg{
				UintArg: v,
			}})
		case int32:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_IntArg{
				IntArg: v,
			}})
		case string:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_StringArg{
				StringArg: v,
			}})

		case []byte:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_BytesArg{
				BytesArg: v,
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	tetragonEvent := &tetragon.ProcessTracepoint{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Subsys:  msg.Subsys,
		Event:   msg.Event,
		Args:    tetragonArgs,
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, msg.Common.Ktime, msg.ProcessKey.Ktime, msg)
		return nil
	}

	if proc != nil {
		tetragonEvent.Process = proc.GetProcessCopy()
		// Use the bpf recorded TID to update the event
		// The cost to get this is relatively high because it requires a
		// deep copyo of the process in order to safely modify it.
		process.UpdateEventProcessTid(tetragonEvent.Process, &msg.Tid)
	}

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: tetragonEvent},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (msg *MsgGenericTracepointUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericTracepointUnix)
	return &t
}

func (msg *MsgGenericTracepointUnix) PolicyInfo() tracingpolicy.PolicyInfo {
	return tracingpolicy.PolicyInfo{
		Name: msg.PolicyName,
		Hook: fmt.Sprintf("tracepoint:%s/%s", msg.Subsys, msg.Event),
	}
}

type MsgGenericKprobeUnix struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           uint64
	Action       uint64
	Tid          uint32
	FuncName     string
	Args         []tracingapi.MsgGenericKprobeArg
	PolicyName   string
}

func (msg *MsgGenericKprobeUnix) Notify() bool {
	return true
}

func (msg *MsgGenericKprobeUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.ProcessKey.Pid, &msg.Tid, timestamp)
}

func (msg *MsgGenericKprobeUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Tid)
}

func (msg *MsgGenericKprobeUnix) HandleMessage() *tetragon.GetEventsResponse {
	k := GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (msg *MsgGenericKprobeUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericKprobeUnix)
	return &t
}

func (msg *MsgGenericKprobeUnix) PolicyInfo() tracingpolicy.PolicyInfo {
	return tracingpolicy.PolicyInfo{
		Name: msg.PolicyName,
		Hook: fmt.Sprintf("kprobe:%s", msg.FuncName),
	}
}

type MsgProcessLoaderUnix struct {
	ProcessKey processapi.MsgExecveKey
	Path       string
	Ktime      uint64
	Buildid    []byte
}

type ProcessLoaderNotify struct {
	tetragon.ProcessLoader
}

func (event *ProcessLoaderNotify) GetParent() *tetragon.Process {
	return nil
}

func (event *ProcessLoaderNotify) SetParent(*tetragon.Process) {
}

func GetProcessLoader(msg *MsgProcessLoaderUnix) *tetragon.ProcessLoader {
	var tetragonProcess *tetragon.Process

	process, _ := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = process.UnsafeGetProcess()
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) || (tetragonProcess.Pid.Value > 1)) {
		tetragonEvent := &ProcessLoaderNotify{}
		tetragonEvent.Process = tetragonProcess
		tetragonEvent.Path = msg.Path
		tetragonEvent.Buildid = msg.Buildid
		ec.Add(nil, tetragonEvent, msg.Ktime, msg.ProcessKey.Ktime, msg)
		return nil
	}

	tetragonEvent := &tetragon.ProcessLoader{
		Process: tetragonProcess,
		Path:    msg.Path,
		Buildid: msg.Buildid,
	}

	return tetragonEvent
}

func (msg *MsgProcessLoaderUnix) Notify() bool {
	return true
}

func (msg *MsgProcessLoaderUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.ProcessKey.Pid, nil, timestamp)
}

func (msg *MsgProcessLoaderUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	LoaderMetricInc(LoaderResolvedRetry)
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgProcessLoaderUnix) HandleMessage() *tetragon.GetEventsResponse {
	LoaderMetricInc(LoaderReceived)
	k := GetProcessLoader(msg)
	if k == nil {
		return nil
	}
	LoaderMetricInc(LoaderResolvedImm)
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessLoader{ProcessLoader: k},
		NodeName: nodeName,
	}
}

func (msg *MsgProcessLoaderUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgProcessLoaderUnix)
	return &t
}

type MsgGenericUprobeUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Tid        uint32
	Path       string
	Symbol     string
	PolicyName string
}

func (msg *MsgGenericUprobeUnix) Notify() bool {
	return true
}

func (msg *MsgGenericUprobeUnix) PolicyInfo() tracingpolicy.PolicyInfo {
	return tracingpolicy.PolicyInfo{
		Name: msg.PolicyName,
		Hook: fmt.Sprintf("uprobe:%s/%s", msg.Path, msg.Symbol),
	}
}

func (msg *MsgGenericUprobeUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.ProcessKey.Pid, &msg.Tid, timestamp)
}

func (msg *MsgGenericUprobeUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Tid)
}

func GetProcessUprobe(event *MsgGenericUprobeUnix) *tetragon.ProcessUprobe {
	var tetragonParent, tetragonProcess *tetragon.Process

	proc, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = proc.UnsafeGetProcess()
		if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
			logger.GetLogger().WithError(err).WithField("processId", tetragonProcess.Pid).
				Debugf("Failed to annotate process with capabilities and namespaces info")
		}
	}

	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	tetragonEvent := &tetragon.ProcessUprobe{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Path:    event.Path,
		Symbol:  event.Symbol,
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}

	if proc != nil {
		tetragonEvent.Process = proc.GetProcessCopy()
		// Use the bpf recorded TID to update the event
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Tid)
	}
	return tetragonEvent
}

func (msg *MsgGenericUprobeUnix) HandleMessage() *tetragon.GetEventsResponse {
	k := GetProcessUprobe(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessUprobe{ProcessUprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (msg *MsgGenericUprobeUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericUprobeUnix)
	return &t
}
