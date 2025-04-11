// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"testing"
)

func TestGrpcExecAncestorsInOrder(t *testing.T) {
	GrpcExecAncestorsInOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecAncestorsOutOfOrder(t *testing.T) {
	GrpcExecAncestorsOutOfOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}
