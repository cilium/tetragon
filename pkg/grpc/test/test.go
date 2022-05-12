// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package test

import (
	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
)

var (
	nodeName = node.GetNodeNameForExport()
)

func HandleTestMessage(msg *testapi.MsgTestEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_TEST:
		res = &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{Test: &fgs.Test{
				Arg0: msg.Arg0,
				Arg1: msg.Arg1,
				Arg2: msg.Arg2,
				Arg3: msg.Arg3,
			}},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleTestMessage: Unhandled event")
	}
	return res
}
