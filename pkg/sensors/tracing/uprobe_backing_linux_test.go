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

// newOverlayContainers fakes an overlay root per container, whose target is a
// hard link to the target in the container's image layer.
func newOverlayContainers(t *testing.T, layerOf map[string]string) rootResolver {
	t.Helper()
	requireOpenat2InRoot(t)
	base := t.TempDir()
	layerRoot := filepath.Join(base, "runtime")
	roots := map[string]*containerRoot{}

	pid := 100
	for id, layer := range layerOf {
		pid++
		layerFile := filepath.Join(layerRoot, layer, testTarget)
		if _, err := os.Stat(layerFile); err != nil {
			require.NoError(t, os.MkdirAll(filepath.Dir(layerFile), 0o755))
			require.NoError(t, os.WriteFile(layerFile, []byte(layer), 0o755))
		}
		proc := filepath.Join(base, "proc", strconv.Itoa(pid))
		root := filepath.Join(proc, "root")
		require.NoError(t, os.MkdirAll(filepath.Join(root, filepath.Dir(testTarget)), 0o755))
		require.NoError(t, os.Link(layerFile, filepath.Join(root, testTarget)))

		var st unix.Stat_t
		require.NoError(t, unix.Stat(layerFile, &st))
		dev := fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev))
		mountinfo := fmt.Sprintf("2 1 %s / /elsewhere rw - overlay overlay rw,lowerdir=/nonexistent\n"+
			"1 1 %s / / rw - overlay overlay rw,lowerdir=/%s\n", dev, dev, layer)
		require.NoError(t, os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(mountinfo), 0o644))
		roots[id] = &containerRoot{
			dir:        root,
			mountinfo:  filepath.Join(proc, "mountinfo"),
			mountPoint: "/",
			layerRoot:  layerRoot,
			release:    func() {},
		}
	}
	return func(_ context.Context, c policyfilter.ContainerChange) (*containerRoot, error) {
		return roots[c.ContainerID], nil
	}
}

func TestReconcilerSharesSensorPerImageLayer(t *testing.T) {
	sensors := newFakeSensors()
	r := newTestReconciler(t, sensors, newOverlayContainers(t, map[string]string{
		"c1": "image-a",
		"c2": "image-a",
		"c3": "image-b",
	}))

	for _, c := range []string{"c1", "c2", "c3"} {
		r.apply(change("pod", c))
	}
	require.Len(t, sensors.binaries(), 2)

	r.apply(removal("pod", "c1"))
	require.Len(t, sensors.binaries(), 2)
	r.apply(removal("pod", "c2"))
	require.Len(t, sensors.binaries(), 1)
}

func TestBackingFileIDKeepsPerContainerKeyWhenUnsure(t *testing.T) {
	requireOpenat2InRoot(t)
	base := t.TempDir()
	layerRoot := filepath.Join(base, "runtime")
	layerApp := filepath.Join(layerRoot, "layer", "sub", "usr", "bin", "app")
	require.NoError(t, os.MkdirAll(filepath.Dir(layerApp), 0o755))
	require.NoError(t, os.WriteFile(layerApp, []byte("elf"), 0o755))

	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), nil, 0o755))
	require.NoError(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))

	mountinfo := filepath.Join(base, "mountinfo")
	require.NoError(t, os.WriteFile(mountinfo, []byte("1 1 0:4242 /sub / rw - overlay overlay rw,lowerdir=/layer\n"), 0o644))
	r := &containerRoot{dir: root, mountinfo: mountinfo, mountPoint: "/", layerRoot: layerRoot, release: func() {}}

	// overlayfs reports the layer file's inode on its own device.
	usesLayerFile := func(target string, change func(*unix.Stat_t)) bool {
		var st unix.Stat_t
		require.NoError(t, unix.Stat(layerApp, &st))
		layerKey := statKey(&st)
		st.Dev = unix.Mkdev(0, 4242)
		change(&st)
		return backingFileID(r, target, &st) == layerKey
	}
	same := func(*unix.Stat_t) {}

	require.True(t, usesLayerFile("/usr/bin/app", same))
	require.False(t, usesLayerFile("/bin/app", same), "symlink in the path")
	require.False(t, usesLayerFile("/usr/bin/app", func(st *unix.Stat_t) { st.Ino++ }), "another file")

	err := unix.Setxattr(layerApp, "user.overlay.metacopy", nil, 0)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skip("user xattrs unsupported")
	}
	require.NoError(t, err)
	require.False(t, usesLayerFile("/usr/bin/app", same), "metacopy layer file")
}

func TestOverlayLayers(t *testing.T) {
	require.Equal(t, []string{"/snap/4/fs", "/snap/3/fs", "/snap/2/fs"},
		overlayLayers("rw,lowerdir=/snap/3/fs:/snap/2/fs,upperdir=/snap/4/fs,workdir=/snap/4/work"))
	require.Equal(t, []string{"/snap/3/fs"}, overlayLayers("ro,lowerdir=/snap/3/fs::/snap/data/fs"))
	require.Empty(t, overlayLayers("rw,relatime"))
}
