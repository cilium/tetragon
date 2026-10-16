// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/mountinfo"
)

// fileKey is the device and inode of a file.
type fileKey struct {
	dev, ino uint64
}

// backingFileID identifies the inode a uprobe on target attaches to, so
// containers whose images share a binary share one uprobe. On overlayfs each
// container root reports its own st_dev, so key the file by the image layer
// holding it, but only when that layer file is surely the one the container
// sees. Otherwise the key stays per container, and replicas report each event
// twice.
func backingFileID(root *containerRoot, target string, st *unix.Stat_t) fileKey {
	// A symlink resolves differently in one layer than in the merged view.
	fd, err := openInRoot(root.dir, target, unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return statKey(st)
	}
	unix.Close(fd)
	layers, rel := overlayLayersFor(root, target, st.Dev)
	// overlayfs serves the file from the first layer that holds it.
	for _, layer := range layers {
		fd, err := openInRoot(layer, rel, unix.RESOLVE_NO_SYMLINKS)
		if err != nil {
			continue
		}
		key, ok := layerFileKey(fd, st)
		unix.Close(fd)
		if ok {
			return key
		}
		break
	}
	return statKey(st)
}

// layerFileKey keys a layer file only when it is the file overlayfs serves as
// merged, and holds the data a uprobe on merged attaches to.
func layerFileKey(fd int, merged *unix.Stat_t) (fileKey, bool) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !sameFile(&st, merged) || isMetacopy(fd) {
		return fileKey{}, false
	}
	return statKey(&st), true
}

// sameFile reports whether a layer file is the one overlayfs serves as merged.
// With its layers on one filesystem, overlayfs passes on all of a file's stat
// but the device, and no one can set a file's change time.
func sameFile(layer, merged *unix.Stat_t) bool {
	return layer.Ino == merged.Ino && layer.Size == merged.Size && layer.Ctim == merged.Ctim
}

// isMetacopy reports whether a layer file holds only metadata, its data being
// in a lower layer. Unless it clearly is not, assume it does.
func isMetacopy(fd int) bool {
	for _, name := range []string{"trusted.overlay.metacopy", "user.overlay.metacopy"} {
		_, err := unix.Getxattr(procSelfFDPath(fd), name, nil)
		if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return true
		}
	}
	return false
}

func statKey(st *unix.Stat_t) fileKey {
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}
}

func overlayLayersFor(root *containerRoot, target string, dev uint64) ([]string, string) {
	infos, err := mountinfo.GetMountInfoAt(root.mountinfo)
	if err != nil {
		return nil, ""
	}
	device := fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
	for _, mi := range infos {
		if mi.StDev != device || mi.FilesystemType != mountinfo.FilesystemTypeOverlay {
			continue
		}
		// A bind mount of the same filesystem may come first.
		rel, ok := pathUnder(mi.MountPoint, filepath.Join(root.mountPoint, filepath.Clean("/"+target)))
		if !ok {
			continue
		}
		var layers []string
		for _, dir := range overlayLayers(mi.SuperOptions) {
			layers = append(layers, filepath.Join(root.layerRoot, dir))
		}
		// The mount may expose a subtree of the overlay.
		return layers, filepath.Join(mi.Root, rel)
	}
	return nil, ""
}

// overlayLayers returns the upper layer then the lower layers, the order
// overlayfs looks a file up in.
func overlayLayers(superOptions string) []string {
	var upper, lower []string
	for opt := range strings.SplitSeq(superOptions, ",") {
		if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
			upper = append(upper, v)
		}
		if v, ok := strings.CutPrefix(opt, "lowerdir="); ok {
			// Data-only layers, after "::", are never looked up by path.
			v, _, _ = strings.Cut(v, "::")
			lower = strings.Split(v, ":")
		}
	}
	return append(upper, lower...)
}

func pathUnder(dir, path string) (string, bool) {
	// Trimmed so the root mount point works like any other.
	rel, ok := strings.CutPrefix(path, strings.TrimSuffix(dir, "/"))
	if !ok || (rel != "" && !strings.HasPrefix(rel, "/")) {
		return "", false
	}
	return rel, true
}
