// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/reader/notify"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"    // NB: needed so that the exec sensor can load the execve probe on its init
	_ "github.com/cilium/tetragon/pkg/sensors/tracing" // NB: needed so that the exec tracing sensor can load its policy handlers on init
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	pft "github.com/cilium/tetragon/pkg/testutils/policyfilter/tester"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "policyconf-test")
	os.Exit(ec)
}

func TestModeSigKill(t *testing.T) {
	if !bpf.HasSignalHelper() {
		t.Skip("skipping test, bpf_send_signal helper not available")
	}

	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pft := pft.Start(t, ctx)

	tp := &tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "tp-test",
			Namespace: "namespace",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{{
				Call:    "sys_getcpu",
				Return:  true,
				Syscall: true,
				ReturnArg: &v1alpha1.KProbeArg{
					Index: 0,
					Type:  "int",
				},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchActions: []v1alpha1.ActionSelector{
						{Action: "Signal", ArgSig: 9},
					},
				}},
			}},
		},
	}

	pft.AddPolicy(t, ctx, tp)

	getcpuProg := testutils.RepoRootPath("contrib/tester-progs/getcpu")
	var progOut string
	var progErr error
	ops := func() {
		progOut, progErr = pft.ProgTester.ExecMayFail(getcpuProg)
		t.Logf("prog:%s out:%q err:%v", getcpuProg, progOut, progErr)
	}

	checkEnforce := func() {
		cnt := perfring.RunTestEventReduceCount(t, ctx, ops, perfring.FilterTestMessages,
			func(x notify.Message) int {
				if kprobe, ok := x.(*tracing.MsgGenericKprobeUnix); ok {
					if strings.HasSuffix(kprobe.FuncName, "sys_getcpu") {
						return 1
					}
					return -1
				}
				return 0
			})
		require.NoError(t, progErr)
		require.Contains(t, progOut, "signal: killed")
		require.Equal(t, cnt[1], 1, fmt.Sprintf("count=%v", cnt))
	}

	checkMonitor := func() {
		cnt := perfring.RunTestEventReduceCount(t, ctx, ops, perfring.FilterTestMessages,
			func(x notify.Message) int {
				if kprobe, ok := x.(*tracing.MsgGenericKprobeUnix); ok {
					if strings.HasSuffix(kprobe.FuncName, "sys_getcpu") {
						return 1
					}
					return -1
				}
				return 0
			})
		require.NoError(t, progErr)
		require.NotContains(t, progOut, "signal: killed")
		require.Contains(t, progOut, "returned without an error")
		require.Equal(t, cnt[1], 1, fmt.Sprintf("count=%v", cnt))
	}

	// finally, we can do the test
	checkEnforce()
	policyconf.SetPolicyMode(tp, policyconf.MonitorMode)
	checkMonitor()
	policyconf.SetPolicyMode(tp, policyconf.EnforceMode)
	checkEnforce()
}
