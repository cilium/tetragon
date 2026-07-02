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

	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/rthooks"
)

// fakeProcFS builds a procFS-like directory: for each pid->cgroup entry it
// writes <dir>/<pid>/cgroup with the given content, plus a couple of non-pid
// entries to exercise the numeric filter.
func fakeProcFS(t *testing.T, pidCgroup map[uint32]string) string {
	t.Helper()
	dir := t.TempDir()
	for pid, cgroup := range pidCgroup {
		pd := filepath.Join(dir, strconv.FormatUint(uint64(pid), 10))
		require.NoError(t, os.Mkdir(pd, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(pd, "cgroup"), []byte(cgroup), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpuinfo"), []byte("x"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "self"), 0o755))
	return dir
}

// resolveContainerRootDir tries CRI first (off by default in tests), then the
// runtime-hook RootDir. The process-cache host PID source was dropped, so with
// CRI off and no runtime-hook entry there is no root.
func TestResolveContainerRootDir(t *testing.T) {
	t.Cleanup(func() { ricRootDirs.Remove("cid-open"); ricRootDirs.Remove("cid-bad") })

	// 1. rthook RootDir present and openable -> used.
	openable := t.TempDir()
	ricRootDirs.Add("cid-open", openable)
	require.Equal(t, openable, resolveContainerRootDir("cid-open", "/procRoot"))

	// 2. rthook RootDir present but not openable, CRI off -> "".
	ricRootDirs.Add("cid-bad", "/no/such/rootdir")
	require.Empty(t, resolveContainerRootDir("cid-bad", "/procRoot"))

	// 3. no rthook entry, CRI off -> "".
	require.Empty(t, resolveContainerRootDir("cid-missing", "/procRoot"))

	// 4. empty container id -> "".
	require.Empty(t, resolveContainerRootDir("", "/procRoot"))
}

// recordContainerRootDir keys the RootDir by the same stripped container id used
// for lookup: arg.Req.ContainerID when set, else derived from the cgroup path.
func TestRecordContainerRootDir(t *testing.T) {
	t.Cleanup(func() { ricRootDirs.Remove("abc123"); ricRootDirs.Remove("deadbeef") })

	// 1. container id taken from the request field when present.
	recordContainerRootDir(&rthooks.CreateContainerArg{
		Req: &tetragon.CreateContainer{ContainerID: "abc123", RootDir: "/run/x/rootfs"},
	})
	got, ok := ricRootDirs.Get("abc123")
	require.True(t, ok)
	require.Equal(t, "/run/x/rootfs", got)

	// 2. container id derived from the cgroup path when the request field is
	//    empty, stripped to the bare hex (matching the lookup key).
	recordContainerRootDir(&rthooks.CreateContainerArg{
		Req: &tetragon.CreateContainer{
			CgroupsPath: "/kubepods/besteffort/pod123/cri-containerd-deadbeef.scope",
			RootDir:     "/run/y/rootfs",
		},
	})
	got, ok = ricRootDirs.Get("deadbeef")
	require.True(t, ok)
	require.Equal(t, "/run/y/rootfs", got)

	// 3. empty RootDir -> not recorded.
	recordContainerRootDir(&rthooks.CreateContainerArg{
		Req: &tetragon.CreateContainer{ContainerID: "noroot"},
	})
	_, ok = ricRootDirs.Get("noroot")
	require.False(t, ok)

	// 4. relative RootDir -> rejected, not recorded.
	recordContainerRootDir(&rthooks.CreateContainerArg{
		Req: &tetragon.CreateContainer{ContainerID: "relroot", RootDir: "rootfs"},
	})
	_, ok = ricRootDirs.Get("relroot")
	require.False(t, ok)
}

func TestContainerIDFromKey(t *testing.T) {
	require.Equal(t, "c1", containerIDFromKey("podA/c1"))
	require.Equal(t, "abc", containerIDFromKey("uid/abc"))
	require.Equal(t, "c", containerIDFromKey("a/b/c"))
	require.Equal(t, "noseparator", containerIDFromKey("noseparator"))
}

func TestPidInContainer(t *testing.T) {
	cid := "d12f66b3dc94acb07e827ce013432100b980f2915e1c7d7530dd554edb9b0ce4"
	procFS := fakeProcFS(t, map[uint32]string{
		8962: "0::/kubelet.slice/kubelet-kubepods.slice/cri-containerd-" + cid + ".scope\n",
		100:  "0::/system.slice/containerd.service\n",
	})
	require.True(t, pidInContainer(procFS, 8962, cid))  // cgroup names the container
	require.False(t, pidInContainer(procFS, 100, cid))  // unrelated process
	require.False(t, pidInContainer(procFS, 4242, cid)) // no such pid
}

// containerHostPID translates the CRI pid into procFS's namespace. With CRI off
// (the test default) the fast path is skipped and it scans procFS for the
// process whose cgroup names the container — the kind/nested-runtime case where
// the CRI-reported pid is not a host pid.
func TestContainerHostPID(t *testing.T) {
	cid := "abc123def456"
	procFS := fakeProcFS(t, map[uint32]string{
		410011: "0::/kubelet.slice/kubelet-kubepods-pod.slice/cri-containerd-" + cid + ".scope\n",
		200:    "0::/system.slice/kubelet.service\n",
	})
	require.Equal(t, uint32(410011), containerHostPID(procFS, cid))

	// no process belongs to the container -> 0.
	require.Equal(t, uint32(0), containerHostPID(procFS, "notpresent"))
}
