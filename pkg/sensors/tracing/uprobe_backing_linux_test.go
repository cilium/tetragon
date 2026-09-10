// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// overlayContainers builds a fake procfs where each container has its own root
// and mount table, as separate overlay mounts do. The file each container sees
// is a distinct inode, so only resolving it in the layer that backs it can
// show that two containers share one binary.
type overlayContainers struct {
	procFS string
	roots  map[string]string
}

func newOverlayContainers(t *testing.T, target string, layerOf map[string]string) *overlayContainers {
	t.Helper()
	requireOpenat2InRoot(t)
	base := t.TempDir()
	oc := &overlayContainers{procFS: filepath.Join(base, "proc"), roots: map[string]string{}}

	layers := map[string]string{}
	for _, name := range layerOf {
		if _, done := layers[name]; done {
			continue
		}
		dir := filepath.Join(base, "layers", name)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(target)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, target), []byte("elf "+name), 0o755))
		layers[name] = dir
	}

	pid := 100
	for id, layer := range layerOf {
		pid++
		root := filepath.Join(oc.procFS, strconv.Itoa(pid), "root")
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(target)), 0o755))
		// The container's own copy stands in for the overlay's view of the
		// layer file: a different inode for the same binary.
		require.NoError(t, os.WriteFile(filepath.Join(root, target), []byte("elf "+layer), 0o755))

		var st unix.Stat_t
		require.NoError(t, unix.Stat(filepath.Join(root, target), &st))
		entry := fmt.Sprintf("%d 1 %d:%d / / rw,relatime - overlay overlay rw,lowerdir=%s\n",
			pid, unix.Major(st.Dev), unix.Minor(st.Dev), layers[layer])
		require.NoError(t, os.WriteFile(filepath.Join(oc.procFS, strconv.Itoa(pid), "mountinfo"), []byte(entry), 0o644))
		oc.roots[id] = root
	}
	return oc
}

func (o *overlayContainers) resolver() rootResolver {
	return func(containerID string) string { return o.roots[containerID] }
}

// The kernel registers a uprobe on the backing inode, so containers running
// the same image binary must share one uprobe. Attaching per container would
// put several consumers on that inode and report an event from each for a
// single execution.
func TestReconcilerSharesAttachmentViaImageLayerOnOverlay(t *testing.T) {
	oc := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "shared",
		"c2": "shared",
	})
	att := newFakeAttacher()
	r := newContainerUprobeReconciler(oc.procFS, "/usr/bin/app", att, oc.resolver())

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2")

	require.Equal(t, 2, r.attachedCount(), "both containers must be reference-counted")
	require.Len(t, att.attachedKeys(), 1,
		"containers sharing an image layer must share one uprobe")

	r.onContainerDel("podA/c1")
	require.Len(t, att.attachedKeys(), 1, "the uprobe must outlive its first container")
	r.onContainerDel("podB/c2")
	require.Empty(t, att.attachedKeys())
}

// Containers running different binaries are different inodes and must each get
// their own uprobe.
func TestReconcilerSeparatesUprobesAcrossImages(t *testing.T) {
	oc := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "image-a",
		"c2": "image-b",
	})
	att := newFakeAttacher()
	r := newContainerUprobeReconciler(oc.procFS, "/usr/bin/app", att, oc.resolver())

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2")

	require.Len(t, att.attachedKeys(), 2, "different binaries must not share a uprobe")
}

// Without a mount table naming an image layer, the container-visible device
// and inode are the identity, which is exact off overlayfs.
func TestBackingFileIDFallsBackToDeviceAndInode(t *testing.T) {
	requireOpenat2InRoot(t)
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	binary := filepath.Join(root, "usr", "bin", "app")
	require.NoError(t, os.WriteFile(binary, []byte("elf"), 0o755))

	var st unix.Stat_t
	require.NoError(t, unix.Stat(binary, &st))
	want := fmt.Sprintf("inode:%d:%d", uint64(st.Dev), st.Ino)

	require.Equal(t, want, backingFileID(t.TempDir(), root, "/usr/bin/app", binary))
}

func TestOverlayLayers(t *testing.T) {
	// overlayfs looks in the upper layer first, then the lower layers in order.
	require.Equal(t, []string{"/snap/4/fs", "/snap/3/fs", "/snap/2/fs"},
		overlayLayers("rw,lowerdir=/snap/3/fs:/snap/2/fs,upperdir=/snap/4/fs,workdir=/snap/4/work,index=off"))
	require.Equal(t, []string{"/snap/3/fs"}, overlayLayers("ro,lowerdir=/snap/3/fs"))
	require.Empty(t, overlayLayers("rw,relatime"))
}

func TestPathUnder(t *testing.T) {
	rel, ok := pathUnder("/", "/usr/bin/app")
	require.True(t, ok)
	require.Equal(t, "/usr/bin/app", rel)

	rel, ok = pathUnder("/data", "/data/bin/app")
	require.True(t, ok)
	require.Equal(t, "/bin/app", rel)

	_, ok = pathUnder("/data", "/database/app")
	require.False(t, ok, "a prefix that is not a path component must not match")

	_, ok = pathUnder("/data", "/usr/bin/app")
	require.False(t, ok)
}
