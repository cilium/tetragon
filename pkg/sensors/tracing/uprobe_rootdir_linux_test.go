// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	testCID     = "d12f66b3dc94acb07e827ce013432100b980f2915e1c7d7530dd554edb9b0ce4"
	testCgroup  = "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + testCID + ".scope"
	otherCgroup = "0::/kubepods.slice/kubepods-pod2.slice/cri-containerd-0123456789.scope"
)

// fakeProc creates <procFS>/<pid> with a root holding a marker file.
func fakeProc(t *testing.T, procFS, pid, ppid, cgroup, nspid string) {
	t.Helper()
	dir := filepath.Join(procFS, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "root"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root", "marker"), []byte(pid), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup+"\n"), 0o644))
	status := "Name:\tapp\nPPid:\t" + ppid + "\nNSpid:\t" + nspid + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644))
}

func requireMarker(t *testing.T, dir, want string) {
	t.Helper()
	marker, err := os.ReadFile(filepath.Join(dir, "marker"))
	require.NoError(t, err)
	require.Equal(t, want, string(marker))
}

func TestOpenContainerProcess(t *testing.T) {
	procFS := t.TempDir()
	fakeProc(t, procFS, "4242", "0", testCgroup, "4242")
	fakeProc(t, procFS, "4343", "0", otherCgroup, "4343")

	fd, err := openContainerProcess(t.Context(), procFS, "4242", testCID)
	require.NoError(t, err)
	root := pinnedContainerRoot(fd)
	requireMarker(t, root.dir, "4242")
	root.release()

	_, err = openContainerProcess(t.Context(), procFS, "4343", testCID)
	require.ErrorIs(t, err, errNotContainerProcess)
}

func TestOpenContainerProcessInNestedRuntime(t *testing.T) {
	procFS := t.TempDir()
	fakeProc(t, procFS, "90", "0", otherCgroup, "90\t2663\t1")
	fakeProc(t, procFS, "100", "90", testCgroup, "100\t2663\t1")
	fakeProc(t, procFS, "95", "0", testCgroup, "95\t3001\t2700")

	fd, err := openContainerProcess(t.Context(), procFS, "2663", testCID)
	require.NoError(t, err)
	root := pinnedContainerRoot(fd)
	requireMarker(t, root.dir, "100")
	root.release()

	// Only the runtime's level counts, as the container can nest deeper.
	_, err = openContainerProcess(t.Context(), procFS, "2700", testCID)
	require.ErrorIs(t, err, errNotContainerProcess)

	fd, err = openParentRoot(procFS, filepath.Join(procFS, "100"))
	require.NoError(t, err)
	defer unix.Close(fd)
	requireMarker(t, procSelfFDPath(fd), "90")
}

func TestContainerRootFromHook(t *testing.T) {
	requireOpenat2InRoot(t)
	procFS := t.TempDir()
	hostRoot := filepath.Join(procFS, "1", "root")
	rootfs := filepath.Join(hostRoot, "run", "rootfs")
	require.NoError(t, os.MkdirAll(rootfs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootfs, "marker"), []byte("rootfs"), 0o644))
	require.NoError(t, os.Symlink("/", filepath.Join(hostRoot, "alias")))

	root, err := containerRootFromHook(procFS, "/run/rootfs")
	require.NoError(t, err)
	requireMarker(t, root.dir, "rootfs")
	root.release()

	for _, rootDir := range []string{"/", "/..", "/alias"} {
		_, err := containerRootFromHook(procFS, rootDir)
		require.ErrorIs(t, err, errHostRootDir, rootDir)
	}
}

func TestCgroupNamesContainer(t *testing.T) {
	require.True(t, cgroupNamesContainer(testCgroup+"\n", testCID))
	require.False(t, cgroupNamesContainer("0::/pod1/"+testCID+"0000\n", testCID))
	require.False(t, cgroupNamesContainer("0::/pod1/x"+testCID+"\n", testCID))
}
