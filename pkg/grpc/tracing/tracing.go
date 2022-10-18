// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package tracing

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/bpf"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/network"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/reader/path"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type MsgGenericTracepointUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Id         int64
	Subsys     string
	Event      string
	Args       []tracingapi.MsgGenericTracepointArg
}

func (msg *MsgGenericTracepointUnix) Notify() bool {
	return true
}

func (msg *MsgGenericTracepointUnix) HandleMessage() *tetragon.GetEventsResponse {
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
		Subsys: msg.Subsys,
		Event:  msg.Event,
		Args:   tetragonArgs,
	}

	return eventcache.AddProcessParent(tetragonEvent, msg, msg.ProcessKey.Pid, msg.ProcessKey.Ktime, msg.Common.Ktime)
}

func (msg *MsgGenericTracepointUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericTracepointUnix)
	return &t
}

type MsgGenericKprobeUnix struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           uint64
	Action       uint64
	FuncName     string
	Args         []tracingapi.MsgGenericKprobeArg
}

func (msg *MsgGenericKprobeUnix) Notify() bool {
	return true
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

func (msg *MsgGenericKprobeUnix) HandleMessage() *tetragon.GetEventsResponse {
	var tetragonArgs []*tetragon.KprobeArgument
	var tetragonReturnArg *tetragon.KprobeArgument

	for _, arg := range msg.Args {
		a := &tetragon.KprobeArgument{}
		switch e := arg.(type) {
		case tracingapi.MsgGenericKprobeArgInt:
			a.Arg = &tetragon.KprobeArgument_IntArg{IntArg: e.Value}
		case tracingapi.MsgGenericKprobeArgUInt:
			a.Arg = &tetragon.KprobeArgument_UintArg{UintArg: e.Value}
		case tracingapi.MsgGenericKprobeArgSize:
			a.Arg = &tetragon.KprobeArgument_SizeArg{SizeArg: e.Value}
		case tracingapi.MsgGenericKprobeArgString:
			a.Arg = &tetragon.KprobeArgument_StringArg{StringArg: e.Value}
		case tracingapi.MsgGenericKprobeArgSock:
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
		case tracingapi.MsgGenericKprobeArgSkb:
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
		case tracingapi.MsgGenericKprobeArgCred:
			capsArg := &tetragon.KprobeCred{
				Permitted:   caps.GetCapabilitiesTypes(e.Permitted),
				Effective:   caps.GetCapabilitiesTypes(e.Effective),
				Inheritable: caps.GetCapabilitiesTypes(e.Inheritable),
			}
			a.Arg = &tetragon.KprobeArgument_CredArg{CredArg: capsArg}
		case tracingapi.MsgGenericKprobeArgBytes:
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
		case tracingapi.MsgGenericKprobeArgFile:
			fileArg := &tetragon.KprobeFile{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_FileArg{FileArg: fileArg}
		case tracingapi.MsgGenericKprobeArgPath:
			pathArg := &tetragon.KprobePath{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_PathArg{PathArg: pathArg}
		case tracingapi.MsgGenericKprobeArgBpfAttr:
			bpfAttrArg := &tetragon.KprobeBpfAttr{
				ProgType: bpf.GetProgType(e.ProgType),
				InsnCnt:  e.InsnCnt,
				ProgName: e.ProgName,
			}
			a.Arg = &tetragon.KprobeArgument_BpfAttrArg{BpfAttrArg: bpfAttrArg}
		case tracingapi.MsgGenericKprobeArgPerfEvent:
			perfEventArg := &tetragon.KprobePerfEvent{
				KprobeFunc:  e.KprobeFunc,
				Type:        bpf.GetPerfEventType(e.Type),
				Config:      e.Config,
				ProbeOffset: e.ProbeOffset,
			}
			a.Arg = &tetragon.KprobeArgument_PerfEventArg{PerfEventArg: perfEventArg}
		case tracingapi.MsgGenericKprobeArgBpfMap:
			bpfMapArg := &tetragon.KprobeBpfMap{
				MapType:    bpf.GetBpfMapType(e.MapType),
				KeySize:    e.KeySize,
				ValueSize:  e.ValueSize,
				MaxEntries: e.MaxEntries,
				MapName:    e.MapName,
			}
			a.Arg = &tetragon.KprobeArgument_BpfMapArg{BpfMapArg: bpfMapArg}
		case tracingapi.MsgGenericKprobeArgUserNamespace:
			nsArg := &tetragon.KprobeUserNamespace{
				Level: &wrapperspb.Int32Value{Value: e.Level},
				Owner: &wrapperspb.UInt32Value{Value: e.Owner},
				Group: &wrapperspb.UInt32Value{Value: e.Group},
				Ns: &tetragon.Namespace{
					Inum: e.NsInum,
				},
			}
			if e.Level == 0 {
				nsArg.Ns.IsHost = true
			}
			a.Arg = &tetragon.KprobeArgument_UserNamespaceArg{UserNamespaceArg: nsArg}
		case tracingapi.MsgGenericKprobeArgCapability:
			cArg := &tetragon.KprobeCapability{
				Value: &wrapperspb.Int32Value{Value: e.Value},
			}
			cArg.Name, _ = caps.GetCapability(e.Value)
			a.Arg = &tetragon.KprobeArgument_CapabilityArg{CapabilityArg: cArg}
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
		FunctionName: msg.FuncName,
		Args:         tetragonArgs,
		Return:       tetragonReturnArg,
		Action:       kprobeAction(msg.Action),
	}

	return eventcache.AddProcessParent(tetragonEvent, msg, msg.ProcessKey.Pid, msg.ProcessKey.Ktime, msg.Common.Ktime)
}

func (msg *MsgGenericKprobeUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericKprobeUnix)
	return &t
}
