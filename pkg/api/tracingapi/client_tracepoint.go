// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type MsgGenericTracepointArg any

type MsgGenericTracepoint struct {
	Common        processapi.MsgCommon       `align:"common"`
	ProcessKey    processapi.MsgExecveKey    `align:"current"`
	Namespaces    processapi.MsgNamespaces   `align:"ns"`
	Capabilities  processapi.MsgCapabilities `align:"caps"`
	FuncID        int64                      `align:"func_id"`
	RetProbeID    uint64                     `align:"retprobe_id"`
	ActionID      uint64                     `align:"action"`
	ActionArgID   uint32                     `align:"action_arg_id"`
	Tid           uint32                     `align:"tid"` // The recorded TID that triggered the event
	KernelStackID int64                      `align:"kernel_stack_id"`
	UserStackID   int64                      `align:"user_stack_id"`
}
