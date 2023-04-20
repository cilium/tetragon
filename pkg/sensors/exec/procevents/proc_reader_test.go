// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListRunningProcs(t *testing.T) {
	procs, err := listRunningProcs("/proc")
	require.NoError(t, err)
	require.NotNil(t, procs)
	require.NotEqual(t, 0, len(procs))

	for _, p := range procs {
		require.NotZero(t, p.pid)
		require.Equal(t, p.pid, p.tid)
	}
}
