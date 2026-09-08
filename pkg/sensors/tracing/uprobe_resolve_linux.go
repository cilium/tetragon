// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Seam for tests to exercise the unsupported-kernel path.
var openat2 = unix.Openat2

var (
	// The container controls what sits at the path: a FIFO would block the ELF
	// read until a writer appears, wedging the reconciler under its lock.
	errNotRegularFile = errors.New("not a regular file")
	errTargetTooLarge = errors.New("target too large")
	errNoContainment  = errors.New(
		"resolvePathInContainer requires openat2(RESOLVE_IN_ROOT) to confine resolution to the container (kernel 5.6+)")
)

// Parsing and hashing a target materializes it in memory, so bound what a
// container can hand us.
const maxTargetFileSize = 1 << 30 // 1 GiB

// hasOpenat2InRoot reports whether the kernel confines path resolution with
// openat2(RESOLVE_IN_ROOT). Probed rather than derived from the kernel
// version, which distributions backport.
func hasOpenat2InRoot() bool {
	dirfd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dirfd)

	fd, err := openat2(dirfd, ".", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// resolveBinaryUnderRoot resolves path inside root and returns an attach path
// plus a cleanup to call only once the uprobe is attached (Relink() after the
// fd closes is a known gap). The inode-pinned "/proc/self/fd/<fd>" it returns
// closes the resolve-to-open TOCTOU window.
func resolveBinaryUnderRoot(root, path string) (string, func(), error) {
	noop := func() {}

	if path == "" {
		return "", noop, errors.New("empty path")
	}
	if root == "" {
		return "", noop, errors.New("empty root directory")
	}

	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", noop, fmt.Errorf("opening root directory %q: %w", root, err)
	}

	relClean := strings.TrimPrefix(filepath.Clean("/"+path), "/")
	if relClean == "" {
		unix.Close(dirfd)
		return "", noop, fmt.Errorf("path %q resolves to the root directory", path)
	}

	fd, err := openat2(dirfd, relClean, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC,
		// Confine symlinks and "..", and block container-planted magic links.
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	unix.Close(dirfd)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
			// Never fall back to an uncontained join.
			return "", noop, errNoContainment
		case errors.Is(err, unix.ENOENT):
			return "", noop, fmt.Errorf("path %q does not exist under root %q: %w", path, root, err)
		default:
			return "", noop, fmt.Errorf("resolving %q under root %q: %w", path, root, err)
		}
	}

	// Vet the target before the caller opens it; the fd pins the inode, so
	// this cannot be raced.
	attachPath := procSelfFDPath(fd)
	var st unix.Stat_t
	if err := unix.Stat(attachPath, &st); err != nil {
		unix.Close(fd)
		return "", noop, fmt.Errorf("stat resolved path %q: %w", attachPath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return "", noop, fmt.Errorf("resolved path %q is %w", attachPath, errNotRegularFile)
	}
	if st.Size > maxTargetFileSize {
		unix.Close(fd)
		return "", noop, fmt.Errorf("resolved path %q is %w: %d bytes (max %d)",
			attachPath, errTargetTooLarge, st.Size, maxTargetFileSize)
	}
	return attachPath, func() { unix.Close(fd) }, nil
}

// dirOpenable reports whether dir can be opened as a directory by the agent.
func dirOpenable(dir string) bool {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
