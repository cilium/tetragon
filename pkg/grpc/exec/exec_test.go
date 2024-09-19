// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"testing"
)

func TestGrpcExecOutOfOrder(t *testing.T) {
	GrpcExecOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecInOrder(t *testing.T) {
	GrpcExecInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecMisingParent(t *testing.T) {
	GrpcExecMisingParent[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcMissingExec(t *testing.T) {
	GrpcMissingExec[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecParentOutOfOrder(t *testing.T) {
	GrpcExecParentOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecCloneInOrder(t *testing.T) {
	GrpcExecCloneInOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecCloneOutOfOrder(t *testing.T) {
	GrpcExecCloneOutOfOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcParentInOrder(t *testing.T) {
	GrpcParentInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoInOrder(t *testing.T) {
	GrpcExecPodInfoInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoOutOfOrder(t *testing.T) {
	GrpcExecPodInfoOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoInOrderAfter(t *testing.T) {
	GrpcExecPodInfoInOrderAfter[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoOutOfOrderAfter(t *testing.T) {
	GrpcExecPodInfoOutOfOrderAfter[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoDelayedOutOfOrder(t *testing.T) {
	GrpcExecPodInfoDelayedOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoDelayedInOrder(t *testing.T) {
	GrpcExecPodInfoDelayedInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcDelayedExecK8sOutOfOrder(t *testing.T) {
	GrpcDelayedExecK8sOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecAncestorsInOrder(t *testing.T) {
	GrpcExecAncestorsInOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecAncestorsOutOfOrder(t *testing.T) {
	GrpcExecAncestorsOutOfOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}
