// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type MsgTestEventUnix struct {
	Msg *testapi.MsgTestEvent
}

func (msg *MsgTestEventUnix) Notify() bool {
	return true
}

func (msg *MsgTestEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, 0, nil, timestamp)
}

func (msg *MsgTestEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgTestEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_TEST:
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_Test{Test: &tetragon.Test{
				Arg0: msg.Msg.Arg0,
				Arg1: msg.Msg.Arg1,
				Arg2: msg.Msg.Arg2,
				Arg3: msg.Msg.Arg3,
			}},
			Time: ktime.ToProto(msg.Msg.Common.Ktime),
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleTestMessage: Unhandled event")
	}
	return res
}

func (msg *MsgTestEventUnix) Cast(o interface{}) notify.Message {
	t := o.(testapi.MsgTestEvent)
	return &MsgTestEventUnix{Msg: &t}
}
