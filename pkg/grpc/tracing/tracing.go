// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/dns"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/path"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	dnsCache          *dns.Cache
	ciliumState       *cilium.State
	eventCache        *eventcache.Cache
	enableCilium      bool
	enableProcessCred bool
	enableProcessNs   bool
}

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
	default:
		return tetragon.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

func (t *Grpc) GetProcessKprobe(event *api.MsgGenericKprobeUnix) *tetragon.ProcessKprobe {
	var tetragonParent, tetragonProcess *tetragon.Process
	var tetragonArgs []*tetragon.KprobeArgument
	var tetragonReturnArg *tetragon.KprobeArgument

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = process.UnsafeGetProcess()
		if err := process.AnnotateProcess(t.enableProcessCred, t.enableProcessNs); err != nil {
			logger.GetLogger().WithError(err).WithField("processId", tetragonProcess.Pid).Debugf("Failed to annotate process with capabilities and namespaces info")
		}
	}

	if parent == nil {
		tetragonParent = &tetragon.Process{}
	} else {
		tetragonParent = parent.GetProcessCopy()
	}

	for _, arg := range event.Args {
		a := &tetragon.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &tetragon.KprobeArgument_IntArg{IntArg: e.Value}
		case api.MsgGenericKprobeArgSize:
			a.Arg = &tetragon.KprobeArgument_SizeArg{SizeArg: e.Value}
		case api.MsgGenericKprobeArgString:
			a.Arg = &tetragon.KprobeArgument_StringArg{StringArg: e.Value}
		case api.MsgGenericKprobeArgSock:
			sockArg := &tetragon.KprobeSock{
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
				SecPathLen:  e.SecPathLen,
				SecPathOlen: e.SecPathOLen,
			}
			a.Arg = &tetragon.KprobeArgument_SkbArg{SkbArg: skbArg}
		case api.MsgGenericKprobeArgCred:
			capsArg := &tetragon.KprobeCred{
				Permitted:   caps.GetCapabilitiesTypes(e.Permitted),
				Effective:   caps.GetCapabilitiesTypes(e.Effective),
				Inheritable: caps.GetCapabilitiesTypes(e.Inheritable),
			}
			a.Arg = &tetragon.KprobeArgument_CredArg{CredArg: capsArg}
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
		case api.MsgGenericKprobeArgFile:
			fileArg := &tetragon.KprobeFile{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_FileArg{FileArg: fileArg}
		case api.MsgGenericKprobeArgPath:
			pathArg := &tetragon.KprobePath{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_PathArg{PathArg: pathArg}
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

	if t.eventCache.Needed(tetragonProcess) {
		t.eventCache.Add(process, tetragonEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

func (t *Grpc) HandleGenericKprobeMessage(msg *api.MsgGenericKprobeUnix) *tetragon.GetEventsResponse {
	k := t.GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (t *Grpc) HandleGenericTracepointMessage(msg *api.MsgGenericTracepointUnix) *tetragon.GetEventsResponse {
	var tetragonParent, tetragonProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		tetragonParent = &tetragon.Process{}
	} else {
		tetragonParent = parent.GetProcessCopy()
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

	if t.eventCache.Needed(tetragonProcess) {
		t.eventCache.Add(process, tetragonEvent, ktime.ToProto(msg.Common.Ktime), msg)
		return nil
	}
	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: tetragonEvent},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func New(cilium *cilium.State,
	dnsCache *dns.Cache, cache *eventcache.Cache,
	ciliumEnable bool,
	enableProcessCred bool,
	enableProcessNs bool,
) *Grpc {
	return &Grpc{
		ciliumState:  cilium,
		dnsCache:     dnsCache,
		eventCache:   cache,
		enableCilium: ciliumEnable,
	}
}
