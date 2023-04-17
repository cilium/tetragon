// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type MsgGenericTracepointArg interface{}

type MsgGenericTracepoint struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           int64
	ThreadId     uint64
	PID          uint32
	TID          uint32
	ActionId     uint64
	ActionArgId  uint32
	Pad          uint32
}
