// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type MsgGenericTracepointArg interface{}

type MsgGenericTracepoint struct {
	Common        processapi.MsgCommon
	ProcessKey    processapi.MsgExecveKey
	Namespaces    processapi.MsgNamespaces
	Capabilities  processapi.MsgCapabilities
	FuncID        int64
	RetProbeID    uint64
	ActionID      uint64
	ActionArgID   uint32
	TID           uint32 // The recorded TID that triggered the event
	KernelStackID int64
	UserStackID   int64
}
