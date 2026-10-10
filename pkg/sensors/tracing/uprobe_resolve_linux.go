// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

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
	fd, err := openInRoot("/", ".", unix.RESOLVE_NO_MAGICLINKS)
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
	fd, err := openInRoot(root, path, unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return nil, st, fmt.Errorf("resolving %q under root %q: %w", path, root, err)
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
	return os.NewFile(uintptr(rfd), filepath.Join(root, path)), st, nil
}

// openInRoot opens path as O_PATH with dir as its root, so ".." and symlinks
// cannot leave dir.
func openInRoot(dir, path string, resolve uint64) (int, error) {
	dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(dirfd)
	return unix.Openat2(dirfd, "."+filepath.Clean("/"+path), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | resolve,
	})
}
