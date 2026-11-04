// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package vmrunner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

func TestPolicytesterService(t *testing.T) {
	conf := &Conf{ExtraArgs: []string{"--ee-bindir=/ee"}}
	sel := &policytest.Selection{Names: []string{"kprobe-lseek"}, AllParams: true}
	ptArgs, err := conf.policytestArgs(sel)
	require.NoError(t, err)
	fname, err := policytesterServiceFile(filepath.Join(t.TempDir(), policytesterService), ptArgs, "")
	require.NoError(t, err)

	unit, err := os.ReadFile(fname)
	require.NoError(t, err)
	require.Equal(t, `"--ee-bindir=/ee" "--all-params" "--" "kprobe-lseek"`, ptArgs)
	require.Contains(t, string(unit), " "+ptArgs+"\n")
	// vmError parses this record
	require.Contains(t, string(unit), `ExecStopPost=/bin/sh -c 'echo "$SERVICE_RESULT $EXIT_CODE $EXIT_STATUS" > /policytests-results/status'`+"\n")
}

func TestUnitArg(t *testing.T) {
	for arg, want := range map[string]string{
		"--set-param=p=/a b": `"--set-param=p=/a b"`,
		"100%":               `"100%%"`,
		"$HOME":              `"$$HOME"`,
		`say "hi" \ bye`:     `"say \"hi\" \\ bye"`,
	} {
		got, err := unitArg(arg)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
}

func TestVMError(t *testing.T) {
	passed := &policytest.ResultsSummary{Total: 2}
	failed := &policytest.ResultsSummary{Total: 2, Errs: 1}

	require.NoError(t, vmError("success 0 0", passed))
	require.NoError(t, vmError("exit-code 1 1", failed))
	require.ErrorIs(t, vmError("timeout killed TERM", failed), errVMFailed)
	require.ErrorIs(t, vmError("", passed), errVMBadStatus)
}
