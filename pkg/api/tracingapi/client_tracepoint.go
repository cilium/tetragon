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
	ActionId     uint64
}

type MsgGenericTracepointUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Id         int64
	Subsys     string
	Event      string
	Args       []MsgGenericTracepointArg
}
