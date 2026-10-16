// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestOpenTracepointPerCPUEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	fds, err := openTracepointPerCPUEvents("syscalls", "sys_enter_lseek")
	require.NoError(t, err)
	require.NotEmpty(t, fds)
	for _, fd := range fds {
		require.NoError(t, unix.Close(fd))
	}
}
