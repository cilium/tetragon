// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package vmrunner

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// The unit in the VM runs the selection the runner was given, with the extra
// arguments ahead of it.
func TestPolicytesterService(t *testing.T) {
	conf := &Conf{ExtraArgs: []string{"--ee-bindir=/ee"}}
	sel := &policytest.Selection{Names: []string{"kprobe-lseek"}, AllParams: true}
	ptArgs, err := conf.policytestArgs(sel)
	require.NoError(t, err)
	fname, err := policytesterServiceFile(filepath.Join(t.TempDir(), policytesterService), ptArgs, "")
	require.NoError(t, err)

	unit, err := os.ReadFile(fname)
	require.NoError(t, err)
	require.Contains(t, string(unit),
		`policytest run --bindir /usr/local/lib/tetragon/tester-progs --output json --output-file /policytests-results/results.json "--ee-bindir=/ee" "--all-params" "--" "kprobe-lseek"`+"\n")
	require.Contains(t, string(unit), `ExecStopPost=/bin/sh -c 'echo "$SERVICE_RESULT $EXIT_CODE $EXIT_STATUS" > /policytests-results/status'`+"\n")

	all := &policytest.Selection{AllTests: true, AllParams: true}
	ptArgs, err = (&Conf{}).policytestArgs(all)
	require.NoError(t, err)
	require.Equal(t, `"--all-tests" "--all-params" "--"`, ptArgs)
}

func TestUnitArg(t *testing.T) {
	for arg, want := range map[string]string{
		"kprobe-lseek":       `"kprobe-lseek"`,
		"--set-param=p=/a b": `"--set-param=p=/a b"`,
		"100%":               `"100%%"`,
		"$HOME":              `"$$HOME"`,
		`say "hi" \ bye`:     `"say \"hi\" \\ bye"`,
	} {
		got, err := unitArg(arg)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := unitArg("a\nb")
	require.ErrorIs(t, err, errUnitArgLine)
}

func TestVMError(t *testing.T) {
	passed := &policytest.ResultsSummary{Total: 2}
	failed := &policytest.ResultsSummary{Total: 2, Errs: 1}
	none := &policytest.ResultsSummary{}

	require.NoError(t, vmError("success 0 0", passed))
	require.ErrorIs(t, vmError("success 0 0", none), policytest.ErrNoResults)
	require.NoError(t, vmError("exit-code 1 1", failed), "failed tests fail tetra, and the results already say so")
	require.ErrorIs(t, vmError("exit-code 1 1", passed), errVMFailed, "tetra failed after passing results")
	require.ErrorIs(t, vmError("exit-code 1 2", failed), errVMFailed, "a crash after a failed result")
	require.ErrorIs(t, vmError("timeout killed TERM", failed), errVMFailed)
	require.ErrorIs(t, vmError("", passed), errVMBadStatus)
}

func TestNewVMRunnerSources(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	_, err := NewVMRunner(context.Background(), log, &Conf{TesterProgsDir: "/tp"})
	require.ErrorIs(t, err, errTetragonSource)
	_, err = NewVMRunner(context.Background(), log, &Conf{TetragonTarball: "/t.tar.gz", TesterProgsDir: "/tp", TesterProgsTarball: "/tp.tar.gz"})
	require.ErrorIs(t, err, errTesterProgsSrc)
}
