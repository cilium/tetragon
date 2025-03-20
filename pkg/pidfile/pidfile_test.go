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

func TestCreatePidFile(t *testing.T) {
	err := os.MkdirAll(defaults.DefaultRunDir, os.ModeDir)
	require.NoError(t, err)

	pid, err := Create()
	require.NoError(t, err)
	require.NotZero(t, pid)

	pid1, err := readPidFile()
	require.NoError(t, err)
	require.NotZero(t, pid1)

	require.Equal(t, pid, pid1)
	err = Delete()
	require.NoError(t, err)

	pid1, err = readPidFile()
	require.ErrorIs(t, err, ErrPidFileAccess)
	require.Zero(t, pid1)
}

func TestIsPidRunning(t *testing.T) {
	pid := os.Getpid()
	strPid := strconv.Itoa(pid)
	isPidRunning := isPidAlive((strPid))
	require.True(t, isPidRunning)
}
