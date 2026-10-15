// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package exec

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper/docker"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func procScanKtime(t *testing.T, pid uint32) uint64 {
	stats, err := proc.GetProcStatStrings(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)))
	require.NoError(t, err)
	ktime, err := proc.GetStatsKtime(stats)
	require.NoError(t, err)
	return ktime
}

func procScanLookup(t *testing.T, m *ebpf.Map, pid uint32) execvemap.ExecveValue {
	var v execvemap.ExecveValue
	require.NoError(t, m.Lookup(&execvemap.ExecveKey{Pid: pid}, &v), "pid %d not in execve_map", pid)
	return v
}

// TestBPFProcScan checks that the execve_map entries added by the BPF process
// scan for processes started before tetragon match what the procfs scan reads.
func TestBPFProcScan(t *testing.T) {
	if !base.BPFProcScanEnabled() {
		t.Skip("BPF process scan not supported")
	}

	// Start the process before loading the base sensor, so that it's not
	// seen by the exec and fork hooks.
	cmd := exec.Command("/bin/sh", "-c", "sleep 1000; true")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := uint32(cmd.Process.Pid)

	// Run the scan directly rather than through GetRunningProcs, to check
	// the recorded entries as well.
	tus.LoadSensor(t, base.GetInitialSensorTest(t))
	entries, err := procevents.RunProcScan()
	require.NoError(t, err)

	// The program and its map are unloaded after the first run.
	_, err = procevents.RunProcScan()
	require.ErrorIs(t, err, procevents.ErrProcScanUnloaded)

	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.GetExecveMap().Name), nil)
	require.NoError(t, err)
	defer m.Close()

	v := procScanLookup(t, m, pid)

	selfPid := uint32(os.Getpid())
	require.Equal(t, pid, v.Process.Pid)
	require.Equal(t, procScanKtime(t, pid), v.Process.Ktime)
	require.Equal(t, selfPid, v.Parent.Pid)
	require.Equal(t, procScanKtime(t, selfPid), v.Parent.Ktime)
	require.Zero(t, v.Nspid, "nspid is only set in containers")
	require.Zero(t, v.Flags&api.EventInInitTree)

	exe, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe"))
	require.NoError(t, err)
	require.Equal(t, exe, string(v.Binary.Path[:v.Binary.PathLength]))
	require.Equal(t, "-c\x00sleep 1000; true\x00", string(v.Args.Buf[:v.Args.Len]))

	_, permitted, effective, inheritable := caps.GetPIDCaps(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "status"))
	require.Equal(t, permitted, v.Capabilities.Permitted)
	require.Equal(t, effective, v.Capabilities.Effective)
	require.Equal(t, inheritable, v.Capabilities.Inheritable)

	for ns, inum := range map[string]uint32{
		"mnt":  v.Namespaces.MntInum,
		"pid":  v.Namespaces.PidInum,
		"net":  v.Namespaces.NetInum,
		"user": v.Namespaces.UserInum,
	} {
		expected, err := namespace.GetPidNsInode(pid, ns)
		require.NoError(t, err)
		require.Equal(t, expected, inum, "%s namespace", ns)
	}

	idx := slices.IndexFunc(entries, func(e procevents.ProcScanEntry) bool { return e.Pid == pid })
	require.NotEqual(t, -1, idx, "pid %d not recorded by the scan", pid)
	e := entries[idx]
	require.Equal(t, v.Process.Ktime, e.Ktime)
	require.Zero(t, e.Flags)
	require.Equal(t, uint32(os.Getuid()), e.Uids[0])
	require.Equal(t, uint32(os.Geteuid()), e.Uids[1])
	require.Equal(t, uint32(os.Getgid()), e.Gids[0])
	require.Equal(t, uint32(os.Getegid()), e.Gids[1])
	wd, err := os.Getwd()
	require.NoError(t, err)
	// Same as procFromScan(), an empty path is the root directory.
	cwd := string(e.Cwd[:e.CwdLen])
	if e.CwdLen == 0 {
		cwd = "/"
	}
	require.Equal(t, wd, cwd)

	// kthreadd: kernel threads are reported with their comm as binary
	kv := procScanLookup(t, m, 2)
	require.Equal(t, "kthreadd", string(kv.Binary.Path[:kv.Binary.PathLength]))
	require.Zero(t, kv.Parent.Pid)
	require.Zero(t, kv.Args.Len)
}

// TestBPFProcScanContainer checks that the container id and the cgroup id
// recorded by the BPF process scan for a container started before tetragon
// match what the procfs scan reads.
func TestBPFProcScanContainer(t *testing.T) {
	if !base.BPFProcScanEnabled() {
		t.Skip("BPF process scan not supported")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	mode, err := cgroups.DetectCgroupMode()
	require.NoError(t, err)
	assert.NotEqual(t, cgroups.CGROUP_UNDEF, mode)

	// Start the container before loading the base sensor, so that its
	// processes are not seen by the exec and fork hooks.
	containerID := docker.Run(t, "--name", "bpf-proc-scan-test", "bash", "bash", "-c", "sleep infinity")
	var pid uint32
	require.Eventually(t, func() bool {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
		if err != nil {
			return false
		}
		p, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
		pid = uint32(p)
		return err == nil && pid != 0
	}, 10*time.Second, 100*time.Millisecond, "container root pid not found")

	tus.LoadSensor(t, base.GetInitialSensorTest(t))
	entries, err := procevents.RunProcScan()
	require.NoError(t, err)

	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.GetExecveMap().Name), nil)
	require.NoError(t, err)
	defer m.Close()

	v := procScanLookup(t, m, pid)
	require.Equal(t, uint32(1), v.Nspid, "container root pid is 1 in its pid namespace")

	idx := slices.IndexFunc(entries, func(e procevents.ProcScanEntry) bool { return e.Pid == pid })
	require.NotEqual(t, -1, idx, "pid %d not recorded by the scan", pid)
	e := entries[idx]
	require.Equal(t, v.Process.Ktime, e.Ktime)

	// Same as procFromScan()
	require.NotEmpty(t, e.Kube.Docker, "cgroup name not recorded by the scan")
	cgroup := cgroups.CgroupNameFromCStr(e.Kube.Docker[:processapi.CGROUP_NAME_LENGTH])
	dockerID, _ := procevents.LookupContainerId(cgroup, true, false)
	require.Equal(t, containerID[:procevents.BpfContainerIdLength], dockerID)

	cgrpid, err := cgroups.CgroupIDFromPID(pid)
	require.NoError(t, err)
	require.Equal(t, cgrpid, e.Kube.Cgrpid)
}
