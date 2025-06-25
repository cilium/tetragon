// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListRunningProcs(t *testing.T) {
	procs, err := listRunningProcs("/proc")
	require.NoError(t, err)
	require.NotNil(t, procs)
	require.NotEmpty(t, procs)

	for _, p := range procs {
		require.NotZero(t, p.pid)
		require.Equal(t, p.pid, p.tid)
	}
}

func TestInInitTreeProcfs(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); (err != nil) || (runtime.GOOS == "windows") {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	containerID := docker.Create(t, "--name", "procfs-in-init-tree-test", "bash", "bash", "-c", "sleep infinity")

	docker.Start(t, "procfs-in-init-tree-test")
	time.Sleep(1 * time.Second)

	rootPIDOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	require.NoError(t, err, "root pid should fetch")
	rootPID, err := strconv.Atoi(strings.TrimSpace(string(rootPIDOutput)))
	require.NoError(t, err, "root pid should parse")

	procs, err := listRunningProcs("/proc")
	require.NoError(t, err)
	require.NotNil(t, procs)
	require.NotEmpty(t, procs)

	inInitTree := make(map[uint32]struct{})
	for _, p := range procs {
		require.NotZero(t, p.pid)
		require.Equal(t, p.pid, p.tid)
		_, v := procToKeyValue(p, inInitTree)
		if v.Process.PID == uint32(rootPID) || v.Parent.PID == uint32(rootPID) {
			isInInitTree := v.Flags&api.EventInInitTree == api.EventInInitTree
			assert.True(t, isInInitTree)
		}
	}
}
