// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/policyfilter"
)

func newOverlayContainers(t *testing.T, target string, layerOf map[string]string) rootResolver {
	t.Helper()
	requireOpenat2InRoot(t)
	base := t.TempDir()
	procFS := filepath.Join(base, "proc")
	// Layer paths are the runtime's, which need not be the host's.
	runtimeRoot := filepath.Join(base, "runtime")
	roots := map[string]*containerRoot{}

	layers := map[string]string{}
	for _, name := range layerOf {
		if _, done := layers[name]; done {
			continue
		}
		dir := filepath.Join("/layers", name)
		require.NoError(t, os.MkdirAll(filepath.Join(runtimeRoot, dir, filepath.Dir(target)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(runtimeRoot, dir, target), []byte("elf "+name), 0o755))
		layers[name] = dir
	}

	pid := 100
	for id, layer := range layerOf {
		pid++
		root := filepath.Join(procFS, strconv.Itoa(pid), "root")
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(target)), 0o755))
		// overlayfs serves the layer's inode, which a hard link stands in for.
		require.NoError(t, os.Link(filepath.Join(runtimeRoot, layers[layer], target), filepath.Join(root, target)))

		var st unix.Stat_t
		require.NoError(t, unix.Stat(filepath.Join(root, target), &st))
		// A bind mount of the same filesystem elsewhere comes first.
		entry := fmt.Sprintf("%d 1 %d:%d / /elsewhere rw - overlay overlay rw,lowerdir=/nonexistent\n"+
			"%d 1 %d:%d / / rw,relatime - overlay overlay rw,lowerdir=%s\n",
			pid+1000, unix.Major(st.Dev), unix.Minor(st.Dev),
			pid, unix.Major(st.Dev), unix.Minor(st.Dev), layers[layer])
		require.NoError(t, os.WriteFile(filepath.Join(procFS, strconv.Itoa(pid), "mountinfo"), []byte(entry), 0o644))
		roots[id] = &containerRoot{
			dir:        root,
			mountinfo:  filepath.Join(procFS, strconv.Itoa(pid), "mountinfo"),
			mountPoint: "/",
			layerRoot:  runtimeRoot,
			release:    func() {},
		}
	}
	return func(_ context.Context, c policyfilter.ContainerChange) (*containerRoot, error) {
		return roots[c.ContainerID], nil
	}
}

func TestReconcilerSharesAttachmentViaImageLayerOnOverlay(t *testing.T) {
	resolver := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "shared",
		"c2": "shared",
	})
	sensors := newFakeSensors()
	r := newContainerUprobeReconciler("generic_uprobe_ric_0", "/usr/bin/app", "", sensors.builder(), resolver)
	t.Cleanup(r.stop)

	r.apply(change("podA", "c1"))
	r.apply(change("podB", "c2"))
	require.Equal(t, []string{"c1", "c2"}, r.containers())
	require.Len(t, sensors.binaries(), 1)

	r.apply(removal("podA", "c1"))
	require.Len(t, sensors.binaries(), 1)
	r.apply(removal("podB", "c2"))
	require.Empty(t, sensors.binaries())
}

func TestReconcilerSeparatesUprobesAcrossImages(t *testing.T) {
	resolver := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "image-a",
		"c2": "image-b",
	})
	sensors := newFakeSensors()
	r := newContainerUprobeReconciler("generic_uprobe_ric_0", "/usr/bin/app", "", sensors.builder(), resolver)
	t.Cleanup(r.stop)

	r.apply(change("podA", "c1"))
	r.apply(change("podB", "c2"))

	require.Len(t, sensors.binaries(), 2)
}

func TestBackingFileIDFallsBackToDeviceAndInode(t *testing.T) {
	root := t.TempDir()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(root, &st))

	require.Equal(t, statKey(&st), backingFileID(testRoot(root), "/usr/bin/app", &st))
}

func TestOverlayLayers(t *testing.T) {
	require.Equal(t, []string{"/snap/4/fs", "/snap/3/fs", "/snap/2/fs"},
		overlayLayers("rw,lowerdir=/snap/3/fs:/snap/2/fs,upperdir=/snap/4/fs,workdir=/snap/4/work,index=off"))
	require.Equal(t, []string{"/snap/3/fs"}, overlayLayers("ro,lowerdir=/snap/3/fs"))
	require.Empty(t, overlayLayers("rw,relatime"))
	// Data-only layers follow "::" and are never looked up by path.
	require.Equal(t, []string{"/snap/3/fs"}, overlayLayers("ro,lowerdir=/snap/3/fs::/snap/data/fs"))
}

func TestPathUnder(t *testing.T) {
	rel, ok := pathUnder("/", "/usr/bin/app")
	require.True(t, ok)
	require.Equal(t, "/usr/bin/app", rel)

	rel, ok = pathUnder("/data", "/data/bin/app")
	require.True(t, ok)
	require.Equal(t, "/bin/app", rel)

	_, ok = pathUnder("/data", "/database/app")
	require.False(t, ok)

	_, ok = pathUnder("/data", "/usr/bin/app")
	require.False(t, ok)
}

func TestBackingFileIDKeepsPerContainerKeyWhenUnsure(t *testing.T) {
	requireOpenat2InRoot(t)
	base := t.TempDir()
	// The layer path is the runtime's, resolved under its root.
	runtimeRoot := filepath.Join(base, "runtime")
	layerApp := filepath.Join(runtimeRoot, "layer", "sub", "usr", "bin", "app")
	require.NoError(t, os.MkdirAll(filepath.Dir(layerApp), 0o755))
	require.NoError(t, os.WriteFile(layerApp, []byte("elf"), 0o755))
	var layerSt unix.Stat_t
	require.NoError(t, unix.Stat(layerApp, &layerSt))

	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), nil, 0o755))
	require.NoError(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))

	// overlayfs reports the layer file's stat under its own device, and the
	// mount exposes the layer's /sub subtree.
	overlayDev := unix.Mkdev(0, 4242)
	entry := "1 1 0:4242 /sub / rw - overlay overlay rw,lowerdir=/layer\n"
	require.NoError(t, os.WriteFile(filepath.Join(base, "mountinfo"), []byte(entry), 0o644))
	r := &containerRoot{dir: root, mountinfo: filepath.Join(base, "mountinfo"), mountPoint: "/", layerRoot: runtimeRoot, release: func() {}}
	key := func(target string, change func(*unix.Stat_t)) (fileKey, fileKey) {
		st := layerSt
		st.Dev = overlayDev
		change(&st)
		return backingFileID(r, target, &st), statKey(&st)
	}
	same := func(*unix.Stat_t) {}

	got, _ := key("/usr/bin/app", same)
	require.Equal(t, statKey(&layerSt), got, "the layer file is trusted")

	got, perContainer := key("/bin/app", same)
	require.Equal(t, perContainer, got, "a symlink in the path")

	got, perContainer = key("/usr/bin/app", func(st *unix.Stat_t) { st.Ino++ })
	require.Equal(t, perContainer, got, "another file of the same size")

	got, perContainer = key("/usr/bin/app", func(st *unix.Stat_t) { st.Ctim.Nsec++ })
	require.Equal(t, perContainer, got, "another change time")

	r.layerRoot = "/"
	got, perContainer = key("/usr/bin/app", same)
	require.Equal(t, perContainer, got, "the layers under another root")
	r.layerRoot = runtimeRoot

	// A metacopy file holds only metadata; the probed data is elsewhere.
	err := unix.Setxattr(layerApp, "user.overlay.metacopy", nil, 0)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skip("user xattrs unsupported")
	}
	require.NoError(t, err)
	require.NoError(t, unix.Stat(layerApp, &layerSt))
	got, perContainer = key("/usr/bin/app", same)
	require.Equal(t, perContainer, got, "a metacopy layer file")
}
