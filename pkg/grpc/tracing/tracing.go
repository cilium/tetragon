// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"encoding/hex"
	"fmt"

	"github.com/cilium/tetragon/pkg/reader/kernel"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/procsyms"
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
	case tracingapi.ActionTrackSock:
		return tetragon.KprobeAction_KPROBE_ACTION_TRACKSOCK
	case tracingapi.ActionUntrackSock:
		return tetragon.KprobeAction_KPROBE_ACTION_UNTRACKSOCK
	case tracingapi.ActionNotifyEnforcer:
		return tetragon.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER
	case tracingapi.ActionCleanupEnforcerNotification:
		return tetragon.KprobeAction_KPROBE_ACTION_CLEANUPENFORCERNOTIFICATION
	default:
		return tetragon.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

func getKprobeArgInt(arg api.MsgGenericKprobeArgInt, a *tetragon.KprobeArgument) {
	if arg.UserSpaceType == gt.GenericUserBpfCmdType {
		a.Arg = &tetragon.KprobeArgument_BpfCmdArg{BpfCmdArg: tetragon.BpfCmd(arg.Value)}
	} else {
		a.Arg = &tetragon.KprobeArgument_IntArg{IntArg: arg.Value}
	}
	a.Label = arg.Label
}

func getKprobeArgument(arg tracingapi.MsgGenericKprobeArg) *tetragon.KprobeArgument {
	a := &tetragon.KprobeArgument{}
	switch e := arg.(type) {
	case api.MsgGenericKprobeArgInt:
		getKprobeArgInt(e, a)
	case api.MsgGenericKprobeArgUInt:
		a.Arg = &tetragon.KprobeArgument_UintArg{UintArg: e.Value}
		a.Label = e.Label
	case api.MsgGenericKprobeArgSize:
		a.Arg = &tetragon.KprobeArgument_SizeArg{SizeArg: e.Value}
		a.Label = e.Label
	case api.MsgGenericKprobeArgLong:
		a.Arg = &tetragon.KprobeArgument_LongArg{LongArg: e.Value}
		a.Label = e.Label
	case api.MsgGenericKprobeArgString:
		a.Arg = &tetragon.KprobeArgument_StringArg{StringArg: e.Value}
		a.Label = e.Label
	case api.MsgGenericKprobeArgNetDev:
		netDevArg := &tetragon.KprobeNetDev{
			Name: e.Name,
		}
		a.Arg = &tetragon.KprobeArgument_NetDevArg{NetDevArg: netDevArg}
		a.Label = e.Label
	case api.MsgGenericKprobeArgSock:
		sockArg := &tetragon.KprobeSock{
			Cookie:   e.Sockaddr,
			Family:   network.InetFamily(e.Family),
			State:    network.TcpState(e.State),
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
			Family:      network.InetFamily(e.Family),
		}
		a.Arg = &tetragon.KprobeArgument_SkbArg{SkbArg: skbArg}
		a.Label = e.Label
	case api.MsgGenericKprobeArgCred:
		credArg := &tetragon.ProcessCredentials{
			Uid:        &wrapperspb.UInt32Value{Value: e.Uid},
			Gid:        &wrapperspb.UInt32Value{Value: e.Gid},
			Euid:       &wrapperspb.UInt32Value{Value: e.Euid},
			Egid:       &wrapperspb.UInt32Value{Value: e.Egid},
			Suid:       &wrapperspb.UInt32Value{Value: e.Suid},
			Sgid:       &wrapperspb.UInt32Value{Value: e.Sgid},
			Fsuid:      &wrapperspb.UInt32Value{Value: e.FSuid},
			Fsgid:      &wrapperspb.UInt32Value{Value: e.FSgid},
			Securebits: caps.GetSecureBitsTypes(e.SecureBits),
		}
		credArg.Caps = &tetragon.Capabilities{
			Permitted:   caps.GetCapabilitiesTypes(e.Cap.Permitted),
			Effective:   caps.GetCapabilitiesTypes(e.Cap.Effective),
			Inheritable: caps.GetCapabilitiesTypes(e.Cap.Inheritable),
		}
		credArg.UserNs = &tetragon.UserNamespace{
			Level: &wrapperspb.Int32Value{Value: e.UserNs.Level},
			Uid:   &wrapperspb.UInt32Value{Value: e.UserNs.Uid},
			Gid:   &wrapperspb.UInt32Value{Value: e.UserNs.Gid},
			Ns: &tetragon.Namespace{
				Inum: e.UserNs.NsInum,
			},
		}
		if e.UserNs.Level == 0 {
			credArg.UserNs.Ns.IsHost = true
		}
		a.Arg = &tetragon.KprobeArgument_ProcessCredentialsArg{ProcessCredentialsArg: credArg}
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
			Path:       e.Value,
			Flags:      path.FilePathFlagsToStr(e.Flags),
			Permission: path.FilePathModeToStr(e.Permission),
		}
		a.Arg = &tetragon.KprobeArgument_FileArg{FileArg: fileArg}
		a.Label = e.Label
	case api.MsgGenericKprobeArgPath:
		pathArg := &tetragon.KprobePath{
			Path:       e.Value,
			Flags:      path.FilePathFlagsToStr(e.Flags),
			Permission: path.FilePathModeToStr(e.Permission),
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
	case api.MsgGenericKprobeArgLoadModule:
		mArg := &tetragon.KernelModule{
			Name:        e.Name,
			SignatureOk: &wrapperspb.BoolValue{Value: e.SigOk != 0},
			Tainted:     kernel.GetTaintedBitsTypes(e.Taints),
		}
		a.Arg = &tetragon.KprobeArgument_ModuleArg{ModuleArg: mArg}
		a.Label = e.Label
	case api.MsgGenericKprobeArgKernelModule:
		mArg := &tetragon.KernelModule{
			Name:    e.Name,
			Tainted: kernel.GetTaintedBitsTypes(e.Taints),
		}
		a.Arg = &tetragon.KprobeArgument_ModuleArg{ModuleArg: mArg}
		a.Label = e.Label
	case api.MsgGenericKprobeArgKernelCapType:
		a.Arg = &tetragon.KprobeArgument_KernelCapTArg{KernelCapTArg: caps.GetCapabilitiesHex(e.Caps)}
		a.Label = e.Label
	case api.MsgGenericKprobeArgCapInheritable:
		a.Arg = &tetragon.KprobeArgument_CapInheritableArg{CapInheritableArg: caps.GetCapabilitiesHex(e.Caps)}
		a.Label = e.Label
	case api.MsgGenericKprobeArgCapPermitted:
		a.Arg = &tetragon.KprobeArgument_CapPermittedArg{CapPermittedArg: caps.GetCapabilitiesHex(e.Caps)}
		a.Label = e.Label
	case api.MsgGenericKprobeArgCapEffective:
		a.Arg = &tetragon.KprobeArgument_CapEffectiveArg{CapEffectiveArg: caps.GetCapabilitiesHex(e.Caps)}
		a.Label = e.Label
	case api.MsgGenericKprobeArgLinuxBinprm:
		lArg := &tetragon.KprobeLinuxBinprm{
			Path:       e.Value,
			Flags:      path.FilePathFlagsToStr(e.Flags),
			Permission: path.FilePathModeToStr(e.Permission),
		}
		a.Arg = &tetragon.KprobeArgument_LinuxBinprmArg{LinuxBinprmArg: lArg}
		a.Label = e.Label
	default:
		logger.GetLogger().WithField("arg", e).Warnf("unexpected type: %T", e)
	}
	return a
}

func GetProcessKprobe(event *MsgGenericKprobeUnix) *tetragon.ProcessKprobe {
	var tetragonParent, tetragonProcess *tetragon.Process
	var tetragonArgs []*tetragon.KprobeArgument
	var tetragonReturnArg *tetragon.KprobeArgument

	proc, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
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
		a := getKprobeArgument(arg)
		if arg.IsReturnArg() {
			tetragonReturnArg = a
		} else {
			tetragonArgs = append(tetragonArgs, a)
		}
	}

	var kernelStackTrace []*tetragon.StackTraceEntry
	for _, addr := range event.KernelStackTrace {
		if addr == 0 {
			// the stack trace from the MsgGenericKprobeUnix is a fixed size
			// array, [unix.PERF_MAX_STACK_DEPTH]uint64, used for binary decode,
			// it might contain multiple zeros to ignore since stack trace might
			// be less than PERF_MAX_STACK_DEPTH most of the time.
			continue
		}
		kernelSymbols, err := ksyms.KernelSymbols()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("stacktrace: failed to read kernel symbols")
			continue
		}
		fnOffset, err := kernelSymbols.GetFnOffset(addr)
		if err != nil {
			// maybe group those errors as they might come in pack
			logger.GetLogger().WithField("address", fmt.Sprintf("0x%x", addr)).Warn("stacktrace: failed to retrieve symbol and offset")
			continue
		}
		entry := &tetragon.StackTraceEntry{
			Offset: fnOffset.Offset,
			Symbol: fnOffset.SymName,
		}
		if option.Config.ExposeStackAddresses {
			entry.Address = addr
		}
		kernelStackTrace = append(kernelStackTrace, entry)
	}

	var userStackTrace []*tetragon.StackTraceEntry
	for _, addr := range event.UserStackTrace {
		if addr == 0 {
			continue
		}
		// TODO extract symbols from procfs
		entry := &tetragon.StackTraceEntry{}
		fsym, err := procsyms.GetFnSymbol(int(event.Msg.Tid), addr)
		if err != nil {
			logger.GetLogger().WithField("address", fmt.Sprintf("0x%x", addr)).Debug("stacktrace: failed to retrieve symbol, offset and module")
			continue
		}
		entry.Offset = fsym.Offset
		entry.Module = fsym.Module
		entry.Symbol = fsym.Name
		if option.Config.ExposeStackAddresses {
			entry.Address = addr
		}
		userStackTrace = append(userStackTrace, entry)
	}

	tetragonEvent := &tetragon.ProcessKprobe{
		Process:          tetragonProcess,
		Parent:           tetragonParent,
		FunctionName:     event.FuncName,
		Args:             tetragonArgs,
		Return:           tetragonReturnArg,
		Action:           kprobeAction(event.Msg.ActionId),
		ReturnAction:     kprobeAction(event.ReturnAction),
		KernelStackTrace: kernelStackTrace,
		UserStackTrace:   userStackTrace,
		PolicyName:       event.PolicyName,
		Message:          event.Message,
		Tags:             event.Tags,
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if proc != nil {
		// At kprobes we report the per thread fields, so take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
	}
	if parent != nil {
		tetragonEvent.Parent = tetragonParent
	}

	return tetragonEvent
}

type MsgGenericTracepointUnix struct {
	Msg        *tracingapi.MsgGenericTracepoint
	Subsys     string
	Event      string
	Args       []tracingapi.MsgGenericTracepointArg
	PolicyName string
	Message    string
	Tags       []string
}

func (msg *MsgGenericTracepointUnix) Notify() bool {
	return true
}

func (msg *MsgGenericTracepointUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.Msg.ProcessKey.Pid, &msg.Msg.Tid, timestamp)
}

func (msg *MsgGenericTracepointUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Msg.Tid)
}

func familyString(family uint16) string {
	switch family {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	}
	return ""
}

func (msg *MsgGenericTracepointUnix) HandleMessage() *tetragon.GetEventsResponse {
	var tetragonParent, tetragonProcess *tetragon.Process

	proc, parent := process.GetParentProcessInternal(msg.Msg.ProcessKey.Pid, msg.Msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.Msg.ProcessKey.Ktime),
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

		case tracingapi.MsgGenericKprobeArgSkb:
			skb := tetragon.KprobeSkb{
				Family:      familyString(v.Family),
				Hash:        v.Hash,
				Len:         v.Len,
				Priority:    v.Priority,
				Mark:        v.Mark,
				Saddr:       v.Saddr,
				Daddr:       v.Daddr,
				Sport:       v.Sport,
				Dport:       v.Dport,
				Proto:       v.Proto,
				Protocol:    network.InetProtocol(uint16(v.Proto)),
				SecPathLen:  v.SecPathLen,
				SecPathOlen: v.SecPathOLen,
			}

			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SkbArg{
				SkbArg: &skb,
			}})

		case tracingapi.MsgGenericKprobeArgSock:
			sk := tetragon.KprobeSock{
				Family:   familyString(v.Family),
				Type:     network.InetType(v.Type),
				Protocol: network.InetProtocol(uint16(v.Protocol)),
				Mark:     v.Mark,
				Priority: v.Priority,
				Saddr:    v.Saddr,
				Daddr:    v.Daddr,
				Sport:    v.Sport,
				Dport:    v.Dport,
				Cookie:   v.Sockaddr,
				State:    network.TcpState(v.State),
			}

			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SockArg{
				SockArg: &sk,
			}})

		case tracingapi.MsgGenericSyscallID:
			tetragonArgs = append(tetragonArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SyscallId{
				SyscallId: &tetragon.SyscallId{
					Id:  v.ID,
					Abi: v.ABI,
				},
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	tetragonEvent := &tetragon.ProcessTracepoint{
		Process:    tetragonProcess,
		Parent:     tetragonParent,
		Subsys:     msg.Subsys,
		Event:      msg.Event,
		Args:       tetragonArgs,
		PolicyName: msg.PolicyName,
		Message:    msg.Message,
		Tags:       msg.Tags,
		Action:     kprobeAction(msg.Msg.ActionId),
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, msg.Msg.Common.Ktime, msg.Msg.ProcessKey.Ktime, msg)
		return nil
	}

	if proc != nil {
		// At tracepoints we report the per thread fields, so take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &msg.Msg.Tid)
	}

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: tetragonEvent},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
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
	Msg              *tracingapi.MsgGenericKprobe
	ReturnAction     uint64
	FuncName         string
	Args             []tracingapi.MsgGenericKprobeArg
	PolicyName       string
	Message          string
	KernelStackTrace [unix.PERF_MAX_STACK_DEPTH]uint64
	UserStackTrace   [unix.PERF_MAX_STACK_DEPTH]uint64
	Tags             []string
}

func (msg *MsgGenericKprobeUnix) Notify() bool {
	return true
}

func (msg *MsgGenericKprobeUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.Msg.ProcessKey.Pid, &msg.Msg.Tid, timestamp)
}

func (msg *MsgGenericKprobeUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Msg.Tid)
}

func (msg *MsgGenericKprobeUnix) HandleMessage() *tetragon.GetEventsResponse {
	k := GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
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
	Msg     *tracingapi.MsgLoader
	Path    string
	Buildid []byte
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

	process, _ := process.GetParentProcessInternal(msg.Msg.ProcessKey.Pid, msg.Msg.ProcessKey.Ktime)
	if process == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.Msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = process.UnsafeGetProcess()
	}

	notifyEvent := &ProcessLoaderNotify{
		ProcessLoader: tetragon.ProcessLoader{
			Process: tetragonProcess,
			Path:    msg.Path,
			Buildid: msg.Buildid,
		},
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(notifyEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) || (tetragonProcess.Pid.Value > 1)) {
		ec.Add(nil, notifyEvent, msg.Msg.Common.Ktime, msg.Msg.ProcessKey.Ktime, msg)
		return nil
	}

	return &notifyEvent.ProcessLoader
}

func (msg *MsgProcessLoaderUnix) Notify() bool {
	return true
}

func (msg *MsgProcessLoaderUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.Msg.ProcessKey.Pid, nil, timestamp)
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
	Msg        *tracingapi.MsgGenericKprobe
	Path       string
	Symbol     string
	PolicyName string
	Message    string
	Args       []tracingapi.MsgGenericKprobeArg
	Tags       []string
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
	return eventcache.HandleGenericInternal(ev, msg.Msg.ProcessKey.Pid, &msg.Msg.Tid, timestamp)
}

func (msg *MsgGenericUprobeUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Msg.Tid)
}

func GetProcessUprobe(event *MsgGenericUprobeUnix) *tetragon.ProcessUprobe {
	var tetragonParent, tetragonProcess *tetragon.Process
	var tetragonArgs []*tetragon.KprobeArgument

	proc, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
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

	for _, arg := range event.Args {
		tetragonArgs = append(tetragonArgs, getKprobeArgument(arg))
	}

	tetragonEvent := &tetragon.ProcessUprobe{
		Process:    tetragonProcess,
		Parent:     tetragonParent,
		Path:       event.Path,
		Symbol:     event.Symbol,
		PolicyName: event.PolicyName,
		Message:    event.Message,
		Args:       tetragonArgs,
		Tags:       event.Tags,
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if proc != nil {
		// At uprobes we report the per thread fields, so take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
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
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
	}
}

func (msg *MsgGenericUprobeUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericUprobeUnix)
	return &t
}

type MsgImaHash struct {
	Algo int32     `align:"algo"`
	Hash [64]uint8 `align:"hash"`
}

type MsgGenericLsmUnix struct {
	Msg        *tracingapi.MsgGenericKprobe
	Hook       string
	Args       []tracingapi.MsgGenericKprobeArg
	PolicyName string
	Message    string
	Tags       []string
	ImaHash    MsgImaHash
}

func (msg *MsgGenericLsmUnix) Notify() bool {
	return true
}

func (msg *MsgGenericLsmUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, msg.Msg.ProcessKey.Pid, &msg.Msg.Tid, timestamp)
}

func (msg *MsgGenericLsmUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, &msg.Msg.Tid)
}

func (msg *MsgGenericLsmUnix) HandleMessage() *tetragon.GetEventsResponse {
	k := GetProcessLsm(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessLsm{ProcessLsm: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
	}
}

func (msg *MsgGenericLsmUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgGenericLsmUnix)
	return &t
}

func (msg *MsgGenericLsmUnix) PolicyInfo() tracingpolicy.PolicyInfo {
	return tracingpolicy.PolicyInfo{
		Name: msg.PolicyName,
		Hook: fmt.Sprintf("lsm:%s", msg.Hook),
	}
}

func GetProcessLsm(event *MsgGenericLsmUnix) *tetragon.ProcessLsm {
	var tetragonParent, tetragonProcess *tetragon.Process
	var tetragonArgs []*tetragon.KprobeArgument

	proc, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
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
		a := getKprobeArgument(arg)
		tetragonArgs = append(tetragonArgs, a)
	}

	tetragonEvent := &tetragon.ProcessLsm{
		Process:      tetragonProcess,
		Parent:       tetragonParent,
		FunctionName: event.Hook,
		Args:         tetragonArgs,
		Action:       kprobeAction(event.Msg.ActionId),
		PolicyName:   event.PolicyName,
		Message:      event.Message,
		Tags:         event.Tags,
	}

	switch event.ImaHash.Algo {
	case 1: // MD5
		tetragonEvent.ImaHash = fmt.Sprintf("md5:%s", hex.EncodeToString(event.ImaHash.Hash[:16]))
	case 2: // SHA1
		tetragonEvent.ImaHash = fmt.Sprintf("sha1:%s", hex.EncodeToString(event.ImaHash.Hash[:20]))
	case 4: // SHA256
		tetragonEvent.ImaHash = fmt.Sprintf("sha256:%s", hex.EncodeToString(event.ImaHash.Hash[:32]))
	case 6: // SHA512
		tetragonEvent.ImaHash = fmt.Sprintf("sha512:%s", hex.EncodeToString(event.ImaHash.Hash[:]))
	case 13: // WP512
		tetragonEvent.ImaHash = fmt.Sprintf("wp512:%s", hex.EncodeToString(event.ImaHash.Hash[:]))
	case 17: // SM3
		tetragonEvent.ImaHash = fmt.Sprintf("sm3:%s", hex.EncodeToString(event.ImaHash.Hash[:32]))

	default:
		logger.GetLogger().Debugf("bpf_ima_inode_hash/bpf_ima_file_hash returned code: %d", event.ImaHash.Algo)
	}

	if tetragonProcess.Pid == nil {
		eventcache.CacheErrors(eventcache.NilProcessPid, notify.EventType(tetragonEvent)).Inc()
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if proc != nil {
		// At kprobes we report the per thread fields, so take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
	}
	if parent != nil {
		tetragonEvent.Parent = tetragonParent
	}

	return tetragonEvent
}

type MsgProcessThrottleUnix struct {
	Type   tetragon.ThrottleType
	Cgroup string
	Ktime  uint64
}

func (msg *MsgProcessThrottleUnix) Notify() bool {
	return true
}

func (msg *MsgProcessThrottleUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgProcessThrottleUnix RetryInternal() was called")
}

func (msg *MsgProcessThrottleUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return fmt.Errorf("Unreachable state: MsgProcessThrottleUnix Retry() was called")
}

func (msg *MsgProcessThrottleUnix) HandleMessage() *tetragon.GetEventsResponse {
	event := &tetragon.ProcessThrottle{
		Type:   msg.Type,
		Cgroup: msg.Cgroup,
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessThrottle{ProcessThrottle: event},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Ktime),
	}
}

func (msg *MsgProcessThrottleUnix) Cast(o interface{}) notify.Message {
	t := o.(MsgProcessThrottleUnix)
	return &t
}
