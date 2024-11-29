// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package progs

import (
	"context"
	"testing"
	"time"

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
	require.Equal(t, "cmd='/bin/echo hello' returned without an error. Combined output was: \"hello\\n\"", out)
	err = pt.Stop()
	require.Nil(t, err)
}
