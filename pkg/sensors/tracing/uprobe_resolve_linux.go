// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Seam for tests to exercise the unsupported-kernel path.
var openat2 = unix.Openat2

var (
	errNotRegularFile = errors.New("not a regular file")
	errTargetTooLarge = errors.New("target too large")
	errNoContainment  = errors.New(
		"resolvePathInContainer requires openat2(RESOLVE_IN_ROOT) to confine resolution to the container (kernel 5.6+)")
)

// Parsing and hashing a target materializes it in memory, so bound what a
// container can hand us.
const maxTargetFileSize = 1 << 30

// Probed rather than derived from the kernel version, which distributions
// backport.
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

// resolveBinaryUnderRoot resolves path inside root, confining symlinks and
// "..", and returns it open for reading: the open file pins the inode, so the
// container cannot swap the binary before the attach. It goes through an
// O_PATH descriptor first because the container controls what sits at the
// path, and opening a FIFO for reading would block.
func resolveBinaryUnderRoot(root, path string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if root == "" {
		return nil, st, errors.New("empty root directory")
	}
	rel := strings.TrimPrefix(filepath.Clean("/"+path), "/")
	if rel == "" {
		return nil, st, fmt.Errorf("path %q resolves to the root directory", path)
	}

	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, fmt.Errorf("opening root directory %q: %w", root, err)
	}
	fd, err := openat2(dirfd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	unix.Close(dirfd)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
			return nil, st, errNoContainment
		case errors.Is(err, unix.ENOENT):
			return nil, st, fmt.Errorf("path %q does not exist under root %q: %w", path, root, err)
		default:
			return nil, st, fmt.Errorf("resolving %q under root %q: %w", path, root, err)
		}
	}
	defer unix.Close(fd)

	if err := unix.Fstat(fd, &st); err != nil {
		return nil, st, fmt.Errorf("stat %q under root %q: %w", path, root, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, st, fmt.Errorf("path %q under root %q is %w", path, root, errNotRegularFile)
	}
	if st.Size > maxTargetFileSize {
		return nil, st, fmt.Errorf("path %q under root %q is %w: %d bytes (max %d)",
			path, root, errTargetTooLarge, st.Size, maxTargetFileSize)
	}
	rfd, err := unix.Open(procSelfFDPath(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, fmt.Errorf("opening %q under root %q: %w", path, root, err)
	}
	return os.NewFile(uintptr(rfd), filepath.Join(root, rel)), st, nil
}
