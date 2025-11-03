// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type MsgGenericTracepointArg any

type MsgGenericTracepoint struct {
	Common        processapi.MsgCommon
	ProcessKey    processapi.MsgExecveKey
	Namespaces    processapi.MsgNamespaces
	Capabilities  processapi.MsgCapabilities
	FuncId        int64
	RetProbeId    uint64
	ActionId      uint64
	ActionArgId   uint32
	Tid           uint32 // The recorded TID that triggered the event
	KernelStackID int64
	UserStackID   int64
}
