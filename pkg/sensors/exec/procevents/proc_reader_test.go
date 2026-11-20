// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package procevents

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/strutils"
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

// TestListRunningProcsInvalidUTF8 checks that the /proc walk copes with a
// process whose exe path, argv and cwd are not valid UTF-8: the raw bytes are
// kept for the BPF maps and the strings used in events are valid UTF-8.
func TestListRunningProcsInvalidUTF8(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d\xb5ir")
	require.NoError(t, os.Mkdir(dir, 0o755))
	// A copy of sh: coreutils can be a multi-call binary that refuses to
	// run under another name.
	exe := filepath.Join(dir, "s\xb5h")
	data, err := os.ReadFile("/bin/sh")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(exe, data, 0o755))

	// read blocks on the open stdin pipe until the process is killed.
	cmd := exec.Command(exe, "-c", "read x", "a\xb5rg")
	cmd.Dir = dir
	_, err = cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := uint32(cmd.Process.Pid)

	ps, err := listRunningProcs("/proc")
	require.NoError(t, err)
	idx := slices.IndexFunc(ps, func(p procs) bool { return p.pid == pid })
	require.NotEqual(t, -1, idx, "pid %d not found", pid)
	p := ps[idx]

	require.Equal(t, []byte(exe), p.exe)
	require.Equal(t, []byte(exe+"\x00-c\x00read x\x00a\xb5rg\x00"), p.cmdline)
	require.Equal(t, strutils.UTF8FromBPFBytes([]byte(exe)), procFilename(&p))
	require.Equal(t, `-c "read x" a�rg`, procArgs(&p))
	cwd, _ := getCWD(pid)
	require.Equal(t, strutils.UTF8FromBPFBytes([]byte(dir)), cwd)
}

func TestProcToKeyValueArgsExcludeArgv0(t *testing.T) {
	p := procs{
		exe:     []byte("/usr/bin/curl"),
		cmdline: []byte("curl\x00--output\x00/tmp/result\x00"),
	}

	_, v := procToKeyValue(p, make(map[uint32]struct{}))

	assert.Equal(t, []byte("--output\x00/tmp/result\x00"), v.Args.Buf[:v.Args.Len])
}

func TestInInitTreeProcfs(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	containerID := docker.Create(t, "--name", "procfs-in-init-tree-test", "bash", "bash", "-c", "sleep infinity")

	docker.Start(t, "procfs-in-init-tree-test")
	time.Sleep(1 * time.Second)

	rootPidOutput, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	require.NoError(t, err, "root pid should fetch")
	rootPid, err := strconv.Atoi(strings.TrimSpace(string(rootPidOutput)))
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
		if v.Process.Pid == uint32(rootPid) || v.Parent.Pid == uint32(rootPid) {
			isInInitTree := v.Flags&api.EventInInitTree == api.EventInInitTree
			assert.True(t, isInInitTree)
		}
	}
}
