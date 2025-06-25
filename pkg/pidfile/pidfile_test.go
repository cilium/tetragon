// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/defaults"
)

func TestCreatePIDFile(t *testing.T) {
	err := os.MkdirAll(defaults.DefaultRunDir, os.ModeDir)
	require.NoError(t, err)

	pid, err := Create()
	require.NoError(t, err)
	require.NotZero(t, pid)

	pid1, err := readPIDFile()
	require.NoError(t, err)
	require.NotZero(t, pid1)

	require.Equal(t, pid, pid1)
	err = Delete()
	require.NoError(t, err)

	pid1, err = readPIDFile()
	require.ErrorIs(t, err, ErrPIDFileAccess)
	require.Zero(t, pid1)
}

func TestIsPIDRunning(t *testing.T) {
	pid := os.Getpid()
	strPID := strconv.Itoa(pid)
	isPIDRunning := isPIDAlive((strPID))
	require.True(t, isPIDRunning)
}
