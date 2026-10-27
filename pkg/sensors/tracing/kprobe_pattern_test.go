// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

// go test -gcflags="" -c ./pkg/sensors/tracing/ -o go-tests/patterns.test
// sudo ./go-tests/patterns.test --bpf-lib ./bpf/objs/ -test.run TestInPattern
func TestInPatternKprobe(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("InPattern requires kernel >= 6.1")
	}

	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "access.log"),
		filepath.Join(dir, "error.log"),
		filepath.Join(dir, "access.txt"),
		filepath.Join(dir, "access.log.bak"),
	}
	for _, path := range paths {
		require.NoError(t, os.WriteFile(path, []byte("test\n"), 0600))
	}

	spec := &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{{
			Call: "security_file_open",
			Args: []v1alpha1.KProbeArg{{Index: 0, Type: "file"}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator: "In",
					Values:   []uint32{observertesthelper.GetMyPid()},
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    0,
					Operator: "InPattern",
					Values:   []string{filepath.Join(dir, "*.log")},
				}},
			}},
		}},
	}
	loadGenericSensorTest(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	seen := map[string]int{}
	ops := func() {
		for _, path := range paths {
			_, err := os.ReadFile(path)
			require.NoError(t, err)
		}
	}
	handler := func(msg notify.Message) error {
		if event, ok := msg.(*tracing.MsgGenericKprobeUnix); ok {
			require.Equal(t, "security_file_open", event.FuncName)
			require.Len(t, event.Args, 1)
			arg, ok := event.Args[0].(tracingapi.MsgGenericKprobeArgFile)
			require.True(t, ok, "expected a file argument")
			seen[arg.Value]++
		}
		return nil
	}
	perfring.RunTest(t, ctx, ops, handler)

	require.Equal(t, map[string]int{paths[0]: 1, paths[1]: 1}, seen)
}

func TestInPatternFentry(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("InPattern requires kernel >= 6.1")
	}

	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "access.log"),
		filepath.Join(dir, "error.log"),
		filepath.Join(dir, "access.txt"),
		filepath.Join(dir, "access.log.bak"),
	}
	for _, path := range paths {
		require.NoError(t, os.WriteFile(path, []byte("test\n"), 0600))
	}

	spec := &v1alpha1.TracingPolicySpec{
		Fentries: []v1alpha1.KProbeSpec{{
			Call: "security_file_open",
			Args: []v1alpha1.KProbeArg{{Index: 0, Type: "file"}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator: "In",
					Values:   []uint32{observertesthelper.GetMyPid()},
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    0,
					Operator: "InPattern",
					Values:   []string{filepath.Join(dir, "*.log")},
				}},
			}},
		}},
	}
	loadGenericSensorTest(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	seen := map[string]int{}
	ops := func() {
		for _, path := range paths {
			_, err := os.ReadFile(path)
			require.NoError(t, err)
		}
	}
	handler := func(msg notify.Message) error {
		if event, ok := msg.(*tracing.MsgGenericKprobeUnix); ok {
			require.Equal(t, "security_file_open", event.FuncName)
			require.Len(t, event.Args, 1)
			arg, ok := event.Args[0].(tracingapi.MsgGenericKprobeArgFile)
			require.True(t, ok, "expected a file argument")
			seen[arg.Value]++
		}
		return nil
	}
	perfring.RunTest(t, ctx, ops, handler)

	require.Equal(t, map[string]int{paths[0]: 1, paths[1]: 1}, seen)
}

func TestInPatternLSM(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("InPattern requires kernel >= 6.1")
	}
	if !bpf.HasLSMPrograms() {
		t.Skip("this test requires BPF LSM support")
	}

	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "access.log"),
		filepath.Join(dir, "error.log"),
		filepath.Join(dir, "access.txt"),
		filepath.Join(dir, "access.log.bak"),
	}
	for _, path := range paths {
		require.NoError(t, os.WriteFile(path, []byte("test\n"), 0600))
	}

	spec := &v1alpha1.TracingPolicySpec{
		LsmHooks: []v1alpha1.LsmHookSpec{{
			Hook: "file_open",
			Args: []v1alpha1.KProbeArg{{Index: 0, Type: "file"}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator: "In",
					Values:   []uint32{observertesthelper.GetMyPid()},
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    0,
					Operator: "InPattern",
					Values:   []string{filepath.Join(dir, "*.log")},
				}},
			}},
		}},
	}
	loadGenericSensorTest(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	seen := map[string]int{}
	ops := func() {
		for _, path := range paths {
			_, err := os.ReadFile(path)
			require.NoError(t, err)
		}
	}
	handler := func(msg notify.Message) error {
		if event, ok := msg.(*tracing.MsgGenericLsmUnix); ok {
			require.Equal(t, "file_open", event.Hook)
			require.Len(t, event.Args, 1)
			arg, ok := event.Args[0].(tracingapi.MsgGenericKprobeArgFile)
			require.True(t, ok, "expected a file argument")
			seen[arg.Value]++
		}
		return nil
	}
	perfring.RunTest(t, ctx, ops, handler)

	require.Equal(t, map[string]int{paths[0]: 1, paths[1]: 1}, seen)

}

func TestInPatternUprobe(t *testing.T) {
	if !config.EnableV61Progs() {
		t.Skip("InPattern requires kernel >= 6.1")
	}
	if !bpf.HasKfunc("bpf_copy_from_user_str") {
		t.Skip("this test requires bpf_copy_from_user_str kfunc support")
	}

	testBin := testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1")
	libUprobe := testutils.RepoRootPath("contrib/tester-progs/libuprobe.so")
	symbols := []string{
		"uprobe_test_lib_string_arg",
		"uprobe_test_lib_string_arg_empty",
		"uprobe_test_lib_string_arg_substring",
		"uprobe_test_lib_string_arg0",
	}

	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:    libUprobe,
			Symbols: symbols,
			Args:    []v1alpha1.KProbeArg{{Index: 0, Type: "string"}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator:    "In",
					Values:      []uint32{observertesthelper.GetMyPid()},
					FollowForks: true,
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    0,
					Operator: "InPattern",
					Values:   []string{"*o*"},
				}},
			}},
		}},
	}
	loadGenericSensorTest(t, spec)

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	seen := map[string]int{}
	ops := func() {
		require.NoError(t, exec.CommandContext(ctx, testBin).Run())
	}
	handler := func(msg notify.Message) error {
		if event, ok := msg.(*tracing.MsgGenericUprobeUnix); ok {
			require.Equal(t, libUprobe, event.Path)
			require.Contains(t, symbols, event.Symbol)
			require.Len(t, event.Args, 1)
			arg, ok := event.Args[0].(tracingapi.MsgGenericKprobeArgString)
			require.True(t, ok, "expected a string argument")
			seen[arg.Value]++
		}
		return nil
	}
	perfring.RunTest(t, ctx, ops, handler)

	require.Equal(t, map[string]int{"hello world!": 1, "one": 1}, seen)
}
