package runtimesecuritypolicy

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgRuntimeSecurity struct {
	// kprobeMsg is the original message
	kprobeMsg *tracing.MsgGenericKprobeUnix

	// xlateFn translates the original kprobe event to a ProcessRuntimeSecurity event
	xlateFn func(og *tracing.MsgGenericKprobeUnix, ev *tetragon.ProcessRuntimeSecurity) error
}

func NewRuntimeSecurity(
	msg *tracing.MsgGenericKprobeUnix,
	xlateFn func(og *tracing.MsgGenericKprobeUnix, ev *tetragon.ProcessRuntimeSecurity) error) *MsgRuntimeSecurity {
	return &MsgRuntimeSecurity{
		kprobeMsg: msg,
		xlateFn:   xlateFn,
	}
}

func (msg *MsgRuntimeSecurity) HandleMessage() *tetragon.GetEventsResponse {
	k := tracing.GetProcessKprobe(msg.kprobeMsg)
	if k == nil {
		return nil
	}

	ev := &tetragon.ProcessRuntimeSecurity{
		Policy: &tetragon.RuntimeSecurityPolicy{
			Name:      msg.kprobeMsg.PolicyName,
			Namespace: "",
		},
	}

	err := msg.Translate(ev)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("kprobeEvent", msg.kprobeMsg).Error("error while translating the runtime security event")
		return nil
	}

	ev.Process = k.Process
	ev.Parent = k.Parent

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessRuntimeSecurity{ProcessRuntimeSecurity: ev},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.kprobeMsg.Msg.Common.Ktime),
	}
}

func (msg *MsgRuntimeSecurity) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return msg.kprobeMsg.RetryInternal(ev, timestamp)
}

func (msg *MsgRuntimeSecurity) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return msg.kprobeMsg.Retry(internal, ev)
}

func (msg *MsgRuntimeSecurity) Notify() bool {
	return msg.kprobeMsg.Notify()
}

func (msg *MsgRuntimeSecurity) Cast(o interface{}) notify.Message {
	t := o.(MsgRuntimeSecurity)
	return &t
}

func (msg *MsgRuntimeSecurity) Translate(ev *tetragon.ProcessRuntimeSecurity) error {
	return msg.xlateFn(msg.kprobeMsg, ev)
}
