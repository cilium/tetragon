// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/fgs"
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

func kprobeAction(act uint64) fgs.KprobeAction {
	switch act {
	case tracingapi.ActionPost:
		return fgs.KprobeAction_KPROBE_ACTION_POST
	case tracingapi.ActionFollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_FOLLOWFD
	case tracingapi.ActionSigKill:
		return fgs.KprobeAction_KPROBE_ACTION_SIGKILL
	case tracingapi.ActionUnfollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_UNFOLLOWFD
	case tracingapi.ActionOverride:
		return fgs.KprobeAction_KPROBE_ACTION_OVERRIDE
	default:
		return fgs.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

func (t *Grpc) GetProcessKprobe(event *api.MsgGenericKprobeUnix) *fgs.ProcessKprobe {
	var fgsParent, fgsProcess *fgs.Process
	var fgsArgs []*fgs.KprobeArgument
	var fgsReturnArg *fgs.KprobeArgument

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		if err := process.AnnotateProcess(t.enableProcessCred, t.enableProcessNs); err != nil {
			logger.GetLogger().WithError(err).WithField("processId", fgsProcess.Pid).Debugf("Failed to annotate process with capabilities and namespaces info")
		}
	}

	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	for _, arg := range event.Args {
		a := &fgs.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &fgs.KprobeArgument_IntArg{IntArg: e.Value}
		case api.MsgGenericKprobeArgSize:
			a.Arg = &fgs.KprobeArgument_SizeArg{SizeArg: e.Value}
		case api.MsgGenericKprobeArgString:
			a.Arg = &fgs.KprobeArgument_StringArg{StringArg: e.Value}
		case api.MsgGenericKprobeArgSock:
			sockArg := &fgs.KprobeSock{
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
			a.Arg = &fgs.KprobeArgument_SockArg{SockArg: sockArg}
		case api.MsgGenericKprobeArgSkb:
			skbArg := &fgs.KprobeSkb{
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
			a.Arg = &fgs.KprobeArgument_SkbArg{SkbArg: skbArg}
		case api.MsgGenericKprobeArgCred:
			capsArg := &fgs.KprobeCred{
				Permitted:   caps.GetCapabilitiesTypes(e.Permitted),
				Effective:   caps.GetCapabilitiesTypes(e.Effective),
				Inheritable: caps.GetCapabilitiesTypes(e.Inheritable),
			}
			a.Arg = &fgs.KprobeArgument_CredArg{CredArg: capsArg}
		case api.MsgGenericKprobeArgBytes:
			if e.OrigSize > uint64(len(e.Value)) {
				a.Arg = &fgs.KprobeArgument_TruncatedBytesArg{
					TruncatedBytesArg: &fgs.KprobeTruncatedBytes{
						OrigSize: e.OrigSize,
						BytesArg: e.Value,
					},
				}
			} else {
				a.Arg = &fgs.KprobeArgument_BytesArg{BytesArg: e.Value}
			}
		case api.MsgGenericKprobeArgFile:
			fileArg := &fgs.KprobeFile{
				Path:  path.MarkUnresolvedPathComponents(path.GenPath(e.Value), e.Flags),
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &fgs.KprobeArgument_FileArg{FileArg: fileArg}
		case api.MsgGenericKprobeArgPath:
			pathArg := &fgs.KprobePath{
				Path:  path.MarkUnresolvedPathComponents(path.GenPath(e.Value), e.Flags),
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &fgs.KprobeArgument_PathArg{PathArg: pathArg}
		default:
			logger.GetLogger().WithField("arg", e).Warnf("unexpected type: %T", e)
		}
		if arg.IsReturnArg() {
			fgsReturnArg = a
		} else {
			fgsArgs = append(fgsArgs, a)
		}
	}

	fgsEvent := &fgs.ProcessKprobe{
		Process:      fgsProcess,
		Parent:       fgsParent,
		FunctionName: event.FuncName,
		Args:         fgsArgs,
		Return:       fgsReturnArg,
		Action:       kprobeAction(event.Action),
	}

	if t.eventCache.Needed(fgsProcess) {
		t.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (t *Grpc) HandleGenericKprobeMessage(msg *api.MsgGenericKprobeUnix) *fgs.GetEventsResponse {
	k := t.GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (t *Grpc) HandleGenericTracepointMessage(msg *api.MsgGenericTracepointUnix) *fgs.GetEventsResponse {
	var fgsParent, fgsProcess *fgs.Process

	process, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	var fgsArgs []*fgs.KprobeArgument
	for _, arg := range msg.Args {
		switch v := arg.(type) {
		case uint64:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{
				SizeArg: v,
			}})
		case string:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{
				StringArg: v,
			}})

		case []byte:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{
				BytesArg: v,
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	fgsEvent := &fgs.ProcessTracepoint{
		Process: fgsProcess,
		Parent:  fgsParent,
		Subsys:  msg.Subsys,
		Event:   msg.Event,
		Args:    fgsArgs,
	}

	if t.eventCache.Needed(fgsProcess) {
		t.eventCache.Add(process, fgsEvent, ktime.ToProto(msg.Common.Ktime), msg)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: fgsEvent},
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
