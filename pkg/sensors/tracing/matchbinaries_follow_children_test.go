// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestMatchBinariesFollowChildren(t *testing.T) {

	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("failed to find 'sh' exec: %v", err)
	}
	tmpShPath, err := testutils.CopyFileToTmp(shPath)
	if err != nil {
		t.Fatalf("failed to copy 'sh' exec: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(tmpShPath)
	})

	event := "sys_enter_getcpu"
	spec := &v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{{
			Subsystem: "syscalls",
			Event:     event,
			Args:      []v1alpha1.KProbeArg{},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchBinaries: []v1alpha1.BinarySelector{{
					Operator: "In",
					Values: []string{
						tmpShPath,
					},
					FollowChildren: true,
				}},
			}},
		}},
	}

	loadGenericSensorTest(t, spec)
	getcpuCnt := 0
	eventFn := func(ev notify.Message) error {
		if tpEvent, ok := ev.(*tracing.MsgGenericTracepointUnix); ok {
			if tpEvent.Event != event {
				return fmt.Errorf("unexpected tracepoint event, %s:%s", tpEvent.Subsys, tpEvent.Event)
			}
			getcpuCnt++
		}
		return nil
	}

	getcpuBin := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	ops := func() {
		cmd := exec.Command(tmpShPath, "-c", getcpuBin)
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run command %s: %v", cmd, err)
		}
	}

	perfring.RunTest(t, ctx, ops, eventFn)
	require.Equal(t, 1, getcpuCnt)
}
