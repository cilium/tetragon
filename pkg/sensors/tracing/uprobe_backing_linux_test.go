// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/policyfilter"
)

func newOverlayContainers(t *testing.T, target string, layerOf map[string]string) (string, rootResolver) {
	t.Helper()
	requireOpenat2InRoot(t)
	base := t.TempDir()
	procFS := filepath.Join(base, "proc")
	// Layers are host paths, reached through the host's root.
	require.NoError(t, os.MkdirAll(filepath.Join(procFS, "1"), 0o755))
	require.NoError(t, os.Symlink("/", filepath.Join(procFS, "1", "root")))
	roots := map[string]*containerRoot{}

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
		root := filepath.Join(procFS, strconv.Itoa(pid), "root")
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(target)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, target), []byte("elf "+layer), 0o755))

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
			release:    func() {},
		}
	}
	return procFS, func(_ context.Context, c policyfilter.ContainerChange) (*containerRoot, error) {
		return roots[c.ContainerID], nil
	}
}

func TestReconcilerSharesAttachmentViaImageLayerOnOverlay(t *testing.T) {
	procFS, resolver := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "shared",
		"c2": "shared",
	})
	sensors := newFakeSensors()
	r := newContainerUprobeReconciler(procFS, "/usr/bin/app", "", sensors.builder(), resolver)
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
	procFS, resolver := newOverlayContainers(t, "usr/bin/app", map[string]string{
		"c1": "image-a",
		"c2": "image-b",
	})
	sensors := newFakeSensors()
	r := newContainerUprobeReconciler(procFS, "/usr/bin/app", "", sensors.builder(), resolver)
	t.Cleanup(r.stop)

	r.apply(change("podA", "c1"))
	r.apply(change("podB", "c2"))

	require.Len(t, sensors.binaries(), 2)
}

func TestBackingFileIDFallsBackToDeviceAndInode(t *testing.T) {
	root := t.TempDir()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(root, &st))

	require.Equal(t, statKey(&st), backingFileID(t.TempDir(), testRoot(root), "/usr/bin/app", &st))
}

func TestOverlayLayers(t *testing.T) {
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
	require.False(t, ok)

	_, ok = pathUnder("/data", "/usr/bin/app")
	require.False(t, ok)
}

func TestBackingFileIDKeepsPerContainerKeyWhenUnsure(t *testing.T) {
	requireOpenat2InRoot(t)
	base := t.TempDir()
	procFS := filepath.Join(base, "proc")
	require.NoError(t, os.MkdirAll(filepath.Join(procFS, "1"), 0o755))
	require.NoError(t, os.Symlink("/", filepath.Join(procFS, "1", "root")))
	layer := filepath.Join(base, "layer")
	require.NoError(t, os.MkdirAll(filepath.Join(layer, "sub", "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(layer, "sub", "usr", "bin", "app"), []byte("elf"), 0o755))

	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))
	app := filepath.Join(root, "usr", "bin", "app")
	var st unix.Stat_t
	key := func(target string) fileKey {
		require.NoError(t, unix.Stat(app, &st))
		// The mount exposes the layer's /sub subtree.
		entry := fmt.Sprintf("1 1 %d:%d /sub / rw - overlay overlay rw,lowerdir=%s\n",
			unix.Major(st.Dev), unix.Minor(st.Dev), layer)
		require.NoError(t, os.WriteFile(filepath.Join(base, "mountinfo"), []byte(entry), 0o644))
		r := &containerRoot{dir: root, mountinfo: filepath.Join(base, "mountinfo"), mountPoint: "/", release: func() {}}
		return backingFileID(procFS, r, target, &st)
	}

	require.NoError(t, os.WriteFile(app, []byte("elf"), 0o755))
	layerKey := key("/usr/bin/app")
	require.NotEqual(t, statKey(&st), layerKey, "the layer file is trusted")

	require.Equal(t, statKey(&st), key("/bin/app"), "a symlink in the path")

	require.NoError(t, os.WriteFile(app, []byte("another build"), 0o755))
	require.Equal(t, statKey(&st), key("/usr/bin/app"), "a layer file of another size")
}
