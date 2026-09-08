// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeProcFS writes <dir>/<pid>/cgroup for each pid and gives the pid its own
// root, distinct from host PID 1's.
func fakeProcFS(t *testing.T, pidCgroup map[uint32]string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "1", "root"), 0o755))
	for pid, cgroup := range pidCgroup {
		pd := filepath.Join(dir, strconv.FormatUint(uint64(pid), 10))
		require.NoError(t, os.MkdirAll(filepath.Join(pd, "root"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(pd, "cgroup"), []byte(cgroup), 0o644))
	}
	// Non-numeric entries the scan must skip.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpuinfo"), []byte("x"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "self"), 0o755))
	return dir
}

// The container root is the root of a process running inside it, found by
// scanning procFS for a cgroup that names the container.
func TestResolveContainerRootDir(t *testing.T) {
	const cid = "d12f66b3dc94acb07e827ce013432100b980f2915e1c7d7530dd554edb9b0ce4"
	procFS := fakeProcFS(t, map[uint32]string{
		4242: "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + cid + ".scope\n",
		200:  "0::/system.slice/kubelet.service\n",
	})

	require.Equal(t, filepath.Join(procFS, "4242", "root"), resolveContainerRootDir(cid, procFS))
	require.Empty(t, resolveContainerRootDir("notpresent", procFS), "no container process, no root")
	require.Empty(t, resolveContainerRootDir("", procFS), "empty container id")
}

// The container id must match a whole cgroup path component, and host-namespace
// helpers such as cri-o's conmon must be skipped.
func TestPidInContainer(t *testing.T) {
	const cid = "d12f66b3dc94acb07e827ce013432100b980f2915e1c7d7530dd554edb9b0ce4"
	cases := []struct {
		name     string
		cgroup   string
		hostRoot bool // shares the host's root, as cri-o's conmon does
		want     bool
	}{
		{name: "crio-<id>.scope", cgroup: "0::/kubepods.slice/kubepods-pod1.slice/crio-" + cid + ".scope", want: true},
		{name: "/docker/<id>", cgroup: "0::/docker/" + cid, want: true},
		{name: "docker-<id>.scope", cgroup: "0::/system.slice/docker-" + cid + ".scope", want: true},
		{name: "conmon shares the host root", cgroup: "0::/kubepods.slice/kubepods-pod1.slice/crio-conmon-" + cid + ".scope", hostRoot: true},
		{name: "id as a prefix of a longer token", cgroup: "0::/kubepods/burstable/pod1/" + cid + "0000"},
		{name: "id as a suffix without a separator", cgroup: "0::/kubepods/burstable/pod1/x" + cid},
		{name: "unrelated process", cgroup: "0::/system.slice/containerd.service"},
	}

	pidOf := func(i int) uint32 { return uint32(100 + i) }
	pidCgroup := map[uint32]string{}
	for i, tc := range cases {
		pidCgroup[pidOf(i)] = tc.cgroup + "\n"
	}
	procFS := fakeProcFS(t, pidCgroup)

	for i, tc := range cases {
		pid := pidOf(i)
		if tc.hostRoot {
			root := filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "root")
			require.NoError(t, os.Remove(root))
			require.NoError(t, os.Symlink(filepath.Join(procFS, "1", "root"), root))
		}
		require.Equal(t, tc.want, pidInContainer(procFS, pid, cid), tc.name)
	}

	inContainer := pidOf(0)
	require.False(t, pidInContainer(procFS, 999, cid), "no procfs entry for this pid")
	require.False(t, pidInContainer(procFS, inContainer, ""), "empty container id matches nothing")

	// A root that cannot be compared with the host's must not be trusted.
	require.NoError(t, os.RemoveAll(filepath.Join(procFS, "1", "root")))
	require.False(t, pidInContainer(procFS, inContainer, cid), "unknown host root fails closed")
}
