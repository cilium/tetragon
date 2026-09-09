// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mountinfo"
)

// backingFileID identifies the file a uprobe on path would really attach to,
// so containers running it share one uprobe.
//
// The kernel registers a uprobe on the file's real inode, so every container
// whose image supplies the same binary ends up on one inode: attaching per
// container would put several consumers on it and report an event from each
// for a single execution. Device and inode do not show that on overlayfs,
// where every container root is its own mount and the same shared file
// therefore reports a different device in each. Resolve the file in the image
// layer holding it instead, and identify that.
//
// Falls back to the device and inode of the container-visible file, which is
// exact for anything that is not overlayfs, and errs towards attaching twice
// rather than towards merging two binaries that only look alike.
func backingFileID(procFS, containerRoot, target, attachPath string) string {
	var st unix.Stat_t
	if err := unix.Stat(attachPath, &st); err != nil {
		// The caller holds attachPath open, so this cannot happen. Key on the
		// container so an unidentified file is never merged with another's.
		return "unidentified:" + containerRoot
	}
	fallback := inodeID(&st)

	layers, rel := overlayLayersFor(procFS, containerRoot, target, st.Dev)
	if len(layers) == 0 {
		return fallback
	}
	// overlayfs serves the file from the first layer that holds it, so take
	// the first that resolves.
	for _, layer := range layers {
		backing, closeFn, err := resolveBinaryUnderRoot(layer, rel)
		if err != nil {
			continue
		}
		var layerSt unix.Stat_t
		err = unix.Stat(backing, &layerSt)
		closeFn()
		if err != nil {
			continue
		}
		return inodeID(&layerSt)
	}
	logger.GetLogger().Debug("uprobe reconciler: no backing file in the image layers",
		"path", rel, "layers", len(layers))
	return fallback
}

// inodeID identifies a file by the device and inode a uprobe registers on.
func inodeID(st *unix.Stat_t) string {
	return fmt.Sprintf("inode:%d:%d", uint64(st.Dev), st.Ino)
}

// overlayLayersFor returns the image layers of the overlay the file lives on,
// and the path to look up within them. The container's own mount table names
// the layers, so this needs no access to the container runtime. It returns no
// layers when the file is not on an overlay the agent can read.
func overlayLayersFor(procFS, containerRoot, target string, dev uint64) ([]string, string) {
	// containerRoot is <procFS>/<pid>/root, so the container's mount table
	// sits next to it.
	infos, err := mountinfo.GetMountInfoAt(filepath.Join(filepath.Dir(containerRoot), "mountinfo"))
	if err != nil {
		return nil, ""
	}
	device := fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
	for _, mi := range infos {
		if mi.StDev != device || mi.FilesystemType != mountinfo.FilesystemTypeOverlay {
			continue
		}
		// Both the mount point and the policy's target are paths inside the
		// container.
		rel, ok := pathUnder(mi.MountPoint, filepath.Clean("/"+target))
		if !ok {
			return nil, ""
		}
		var layers []string
		for _, dir := range overlayLayers(mi.SuperOptions) {
			// The layers are paths in the host's mount namespace, which the
			// agent usually reaches only through the host's own root.
			for _, candidate := range []string{dir, filepath.Join(procFS, "1", "root", dir)} {
				if dirOpenable(candidate) {
					layers = append(layers, candidate)
					break
				}
			}
		}
		return layers, rel
	}
	return nil, ""
}

// overlayLayers returns the overlay's upper layer followed by its lower
// layers, the order in which overlayfs itself looks a file up.
func overlayLayers(superOptions string) []string {
	var upper, lower []string
	for opt := range strings.SplitSeq(superOptions, ",") {
		if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
			upper = append(upper, v)
		}
		if v, ok := strings.CutPrefix(opt, "lowerdir="); ok {
			lower = strings.Split(v, ":")
		}
	}
	return append(upper, lower...)
}

// pathUnder returns path relative to dir, and whether it is under it.
func pathUnder(dir, path string) (string, bool) {
	// Trimming makes the root mount point behave like any other.
	rel, ok := strings.CutPrefix(path, strings.TrimSuffix(dir, "/"))
	if !ok || (rel != "" && !strings.HasPrefix(rel, "/")) {
		return "", false
	}
	return rel, true
}
