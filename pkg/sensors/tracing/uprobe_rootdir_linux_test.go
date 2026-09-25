// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const testCID = "d12f66b3dc94acb07e827ce013432100b980f2915e1c7d7530dd554edb9b0ce4"

// fakeProc creates <procFS>/<pid> with a root holding a marker file, a
// cgroup, and an NSpid line.
func fakeProc(t *testing.T, procFS, pid, cgroup, nspid string) {
	t.Helper()
	dir := filepath.Join(procFS, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "root"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root", "marker"), []byte(pid), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tapp\nNSpid:\t"+nspid+"\n"), 0o644))
}

func fdClosed(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return errors.Is(err, unix.EBADF)
}

func requirePinned(t *testing.T, fd int, wantPid string) {
	t.Helper()
	root := pinnedContainerRoot(fd)
	marker, err := os.ReadFile(filepath.Join(root.dir, "marker"))
	require.NoError(t, err)
	require.Equal(t, wantPid, string(marker))
	require.Equal(t, "/", root.mountPoint)
	require.Equal(t, filepath.Join(procSelfFDPath(fd), "mountinfo"), root.mountinfo)
	root.release()
	require.True(t, fdClosed(fd))
}

const (
	testCgroup  = "0::/../../kubepods.slice/kubepods-pod1.slice/cri-containerd-" + testCID + ".scope"
	otherCgroup = "0::/kubepods.slice/kubepods-pod2.slice/cri-containerd-0123456789.scope"
)

func TestOpenContainerProcess(t *testing.T) {
	procFS := t.TempDir()
	fakeProc(t, procFS, "4242", testCgroup, "4242\t1")
	// Another process that a reused PID could leave at the CRI pid.
	fakeProc(t, procFS, "4343", otherCgroup, "4343")

	fd, err := openContainerProcess(t.Context(), procFS, "4242", testCID)
	require.NoError(t, err)
	requirePinned(t, fd, "4242")

	_, err = openContainerProcess(t.Context(), procFS, "4343", testCID)
	require.ErrorIs(t, err, errNotContainerProcess)
}

func TestOpenContainerProcessInNestedRuntime(t *testing.T) {
	// The runtime, as in a kind node, numbers processes one namespace in.
	procFS := t.TempDir()
	fakeProc(t, procFS, "90", otherCgroup, "90\t2663\t1")
	fakeProc(t, procFS, "100", testCgroup, "100\t2663\t1")
	fakeProc(t, procFS, "110", testCgroup, "110\t2664\t2")

	fd, err := openContainerProcess(t.Context(), procFS, "2663", testCID)
	require.NoError(t, err)
	requirePinned(t, fd, "100")

	_, err = openContainerProcess(t.Context(), procFS, "2665", testCID)
	require.ErrorIs(t, err, errNotContainerProcess)

	// A process in the container can make a deeper PID namespace and take
	// any PID there, so only the runtime's level counts.
	fakeProc(t, procFS, "95", testCgroup, "95\t3001\t2700")
	_, err = openContainerProcess(t.Context(), procFS, "2700", testCID)
	require.ErrorIs(t, err, errNotContainerProcess)
}

func TestOpenContainerProcessHonoursContext(t *testing.T) {
	procFS := t.TempDir()
	fakeProc(t, procFS, "100", testCgroup, "100\t2663\t1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := openContainerProcess(ctx, procFS, "2663", testCID)
	require.ErrorIs(t, err, context.Canceled)
}

func TestContainerRootFromHook(t *testing.T) {
	requireOpenat2InRoot(t)
	procFS := t.TempDir()
	hostRoot := filepath.Join(procFS, "1", "root")
	rootfs := filepath.Join(hostRoot, "run", "task", "abc", "rootfs")
	require.NoError(t, os.MkdirAll(rootfs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootfs, "marker"), nil, 0o644))
	require.NoError(t, os.Symlink("/", filepath.Join(hostRoot, "alias")))

	for _, rootDir := range []string{"/run/task/abc/rootfs", "../../run/task/abc/rootfs"} {
		root, err := containerRootFromHook(procFS, rootDir)
		require.NoError(t, err, rootDir)
		require.FileExists(t, filepath.Join(root.dir, "marker"))
		require.Equal(t, filepath.Join(procFS, "1", "mountinfo"), root.mountinfo)
		require.Equal(t, "/run/task/abc/rootfs", root.mountPoint)
		root.release()
	}

	for _, rootDir := range []string{"/", ".", "/..", "/alias"} {
		_, err := containerRootFromHook(procFS, rootDir)
		require.ErrorIs(t, err, errHostRootDir, rootDir)
	}

	_, err := containerRootFromHook(procFS, "/run/task/missing/rootfs")
	require.ErrorIs(t, err, unix.ENOENT)
}

func TestCgroupNamesContainer(t *testing.T) {
	for cgroup, want := range map[string]bool{
		"0::/kubepods.slice/kubepods-pod1.slice/crio-" + testCID + ".scope": true,
		"0::/docker/" + testCID:                           true,
		"0::/system.slice/docker-" + testCID + ".scope":   true,
		"0::/kubepods/burstable/pod1/" + testCID + "0000": false,
		"0::/kubepods/burstable/pod1/x" + testCID:         false,
		"0::/system.slice/containerd.service":             false,
	} {
		require.Equal(t, want, cgroupNamesContainer(cgroup+"\n", testCID), cgroup)
	}
}
