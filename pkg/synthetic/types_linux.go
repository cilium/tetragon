// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// types_linux.go registers Tetragon event types for JSON serialization.
// This file contains Linux-specific type registrations.
package synthetic

import (
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
)

func init() {
	// Register top-level event types
	RegisterType((*exec.MsgExecveEventUnix)(nil))
	RegisterType((*exec.MsgExitEventUnix)(nil))
	RegisterType((*exec.MsgCloneEventUnix)(nil))
	RegisterType((*exec.MsgCgroupEventUnix)(nil))
	RegisterType((*exec.MsgKThreadInitUnix)(nil))
	RegisterType((*readyapi.MsgTetragonReady)(nil))
	RegisterType((*tracing.MsgGenericKprobeUnix)(nil))

	// Register all MsgGenericKprobeArg types for JSON serialization
	RegisterType((*tracingapi.MsgGenericKprobeArgPath)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgFile)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgString)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgBytes)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgInt)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgUInt)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgSize)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgLong)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgSock)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgSkb)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgSockaddr)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgNetDev)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgCred)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgCapability)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgKernelCapType)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgCapInheritable)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgCapPermitted)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgCapEffective)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgLinuxBinprm)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgUserNamespace)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgLoadModule)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgKernelModule)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgBpfAttr)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgBpfProg)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgPerfEvent)(nil))
	RegisterType((*tracingapi.MsgGenericKprobeArgBpfMap)(nil))
}
