// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

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
	_ "github.com/cilium/tetragon/pkg/sensors/exec"           // NB: needed so that the exec sensor can load the execve probe on its init
	stracing "github.com/cilium/tetragon/pkg/sensors/tracing" // NB: needed so that the exec tracing sensor can load its policy handlers on init
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

func TestModeEnforcer(t *testing.T) {
	// NB: the policy below checks for both enforcer and override at the same time, which is why
	// we need both (and, also, why fmod_ret is not enough)
	if !bpf.HasSignalHelper() {
		t.Skip("skipping test, bpf_send_signal helper not available")
	}
	if !bpf.HasOverrideHelper() {
		t.Skip("skipping test, neither bpf_override_return not available")
	}

	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	pft := pft.Start(t, ctx)

	polName := "tp-test"
	polNamespace := "namespace"
	tp := &tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      polName,
			Namespace: polNamespace,
		},
		Spec: v1alpha1.TracingPolicySpec{
			Enforcers: []v1alpha1.EnforcerSpec{{
				// NB: add another enforcer call so that we can just check the map
				Calls: []string{"sys_lseek"},
			}},
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
						{Action: "NotifyEnforcer", ArgSig: 9},
						{Action: "Override", ArgError: -1},
					},
				}},
			}},
		},
	}

	pft.AddPolicy(t, ctx, tp)

	pid := pft.ProgTester.Cmd.Process.Pid

	var cmdOut string
	var cmdErr error
	ops := func() {
		cmdOut, cmdErr = pft.ProgTester.Command("getcpu")
		t.Logf("command getcpu out:%q err:%v", cmdOut, cmdErr)
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
		require.NoError(t, cmdErr)
		require.Equal(t, cnt[1], 1, fmt.Sprintf("count=%v", cnt))
		enfDump, enfDumpErr := stracing.DumpEnforcerMap(polName, polNamespace)
		require.NoError(t, enfDumpErr)
		require.Len(t, enfDump, 1)
		require.Contains(t, cmdOut, "operation not permitted")
		for key, val := range enfDump {
			require.Equal(t, pid, int(key.PidTgid>>32))
			require.Equal(t, val.Sig, int16(9))
			break
		}
	}

	resetEnforcerMap := func() {
		err := stracing.ResetEnforcerMap(t, polName, polNamespace)
		require.NoError(t, err)
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
		require.NoError(t, cmdErr)
		require.Equal(t, cnt[1], 1, fmt.Sprintf("count=%v", cnt))
		require.NotContains(t, cmdOut, "operation not permitted")
		enfDump, enfDumpErr := stracing.DumpEnforcerMap(polName, polNamespace)
		require.NoError(t, enfDumpErr)
		require.Len(t, enfDump, 0)
	}

	// finally, we can do the test
	checkEnforce()
	resetEnforcerMap()
	policyconf.SetPolicyMode(tp, policyconf.MonitorMode)
	checkMonitor()
	resetEnforcerMap()
	policyconf.SetPolicyMode(tp, policyconf.EnforceMode)
	checkEnforce()
}
