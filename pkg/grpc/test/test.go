// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package test

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgTestEventUnix struct {
	testapi.MsgTestEvent
}

func (msg *MsgTestEventUnix) Notify() bool {
	return true
}

func (msg *MsgTestEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_Test{Test: &tetragon.Test{
			Arg0: msg.Arg0,
			Arg1: msg.Arg1,
			Arg2: msg.Arg2,
			Arg3: msg.Arg3,
		}},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (msg *MsgTestEventUnix) Cast(o interface{}) notify.Message {
	t := o.(testapi.MsgTestEvent)
	return &MsgTestEventUnix{MsgTestEvent: t}
}
