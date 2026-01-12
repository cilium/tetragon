// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestCelExpr(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	mypid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", mypid)
	myPidMatchPIDs := []v1alpha1.PIDSelector{{
		Operator:       "In",
		IsNamespacePID: false,
		FollowForks:    true,
		Values:         []uint32{uint32(mypid)},
	}}

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	tp := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "lseek-celexpr",
		},
		Spec: v1alpha1.TracingPolicySpec{
			Options: []v1alpha1.OptionSpec{{
				Name:  "disable-kprobe-multi",
				Value: "1",
			}},
			KProbes: []v1alpha1.KProbeSpec{
				{
					Call:    "sys_lseek",
					Syscall: true,
					Args: []v1alpha1.KProbeArg{
						{Index: 0, Type: "int"},
						{Index: 1, Type: "int"},
						{Index: 2, Type: "int"},
					},
					Selectors: []v1alpha1.KProbeSelector{{
						MatchPIDs: myPidMatchPIDs,
						MatchArgs: []v1alpha1.ArgSelector{{
							Args:     []uint32{0, 1, 2},
							Operator: "CelExpr",
							Values: []string{
								"arg0 - int32(10) == arg1 + int32(5)",
							},
						}},
					}},
				},
			},
		},
	}

	eventCounter := 0
	loadGenericSensorTest(t, &tp.Spec)
	perfring.RunTest(t, ctx,
		func() {
			t.Logf("Calling lseek(-1,-16,0)")
			unix.Seek(-1, -16, 0)
			t.Logf("Calling lseek(-1,-17,0)")
			unix.Seek(-1, -17, 0)
		},
		func(ev notify.Message) error {
			if kpEvent, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
				if kpEvent.FuncName != arch.AddSyscallPrefixTestHelper(t, "sys_lseek") {
					return fmt.Errorf("unexpected kprobe event, func:%s", kpEvent.FuncName)
				}
				if len(kpEvent.Args) != 3 {
					return fmt.Errorf("unexpected kprobe arguments: %+v", kpEvent.Args)
				}
				eventCounter++
			}
			return nil
		},
	)
	require.Equal(t, 1, eventCounter)
}
