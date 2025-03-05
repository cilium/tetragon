// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package progs

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestPing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pt := StartTester(t, ctx)
	err := pt.Ping()
	require.NoError(t, err)
	err = pt.Stop()
	require.Nil(t, err)
}

func TestExec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pt := StartTester(t, ctx)
	out, err := pt.Exec("/bin/echo hello")
	require.NoError(t, err)
	require.Equal(t, "cmd=\"/bin/echo hello\" returned without an error. Combined output was: \"hello\\n\"", out)
	err = pt.Stop()
	require.Nil(t, err)
}

func TestSigkill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raisesigkillProg := testutils.RepoRootPath("contrib/tester-progs/raisesigkill")
	pt := StartTester(t, ctx)
	out, err := pt.ExecMayFail(raisesigkillProg)
	require.NoError(t, err)
	require.Contains(t, out, "signal: killed")
	err = pt.Stop()
	require.Nil(t, err)
}
