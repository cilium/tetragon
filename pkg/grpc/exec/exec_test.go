// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

// go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/watcher"
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

// A procfs exec event is stamped with its process's procfs start time, so its
// time is the process start time whichever clock BPF stamps with. The two
// only drift apart on a host that has suspended since boot.
func TestGrpcProcfsExecTimeIsProcessStartTime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		docker string
	}{
		{name: "sent", docker: ""},
		// Missing pod info holds the event in the event cache.
		{name: "cached", docker: "fake_container_container_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			AllEvents = nil
			option.Config.EnableK8s = true
			fakeWatcher := watcher.NewFakeK8sWatcher(nil)
			dn := InitEnv[*MsgExecveEventUnix, *MsgExitEventUnix](t, fakeWatcher)

			if e := procfsInitExec(tc.docker).HandleMessage(); e != nil {
				AllEvents = append(AllEvents, e)
			}
			fakeWatcher.AddPod(dummyPod)
			dn.WaitNotifier(1)

			require.Len(t, AllEvents, 1)
			ev := AllEvents[0]
			assert.WithinDuration(t, ev.GetProcessExec().Process.StartTime.AsTime(), ev.Time.AsTime(), time.Second)
		})
	}
}

// procfsInitExec is the exec event the procfs walk emits for init, which
// needs no parent.
func procfsInitExec(docker string) *MsgExecveEventUnix {
	const startKtime = 4200000000
	return &MsgExecveEventUnix{Unix: tetragonAPI.MsgExecveEventUnix{
		Msg:  tetragonAPI.MsgExecveEvent{Common: tetragonAPI.MsgCommon{Ktime: startKtime}},
		Kube: tetragonAPI.MsgK8sUnix{Docker: docker},
		Process: tetragonAPI.MsgProcess{
			PID:      1,
			TID:      1,
			Flags:    api.EventProcFS,
			Ktime:    startKtime,
			Filename: "/sbin/init",
		},
	}}
}
