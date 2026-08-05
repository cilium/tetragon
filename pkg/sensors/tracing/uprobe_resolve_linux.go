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
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
)

// openat2UnsupportedOnce rate-limits the missing-openat2 warning: support is
// kernel-global, so warning once per agent avoids per-container/resync spam.
var openat2UnsupportedOnce sync.Once

// openat2 is a seam so tests can exercise the no-openat2 lexical fallback on
// kernels that do support it.
var openat2 = unix.Openat2

// errNotRegularFile marks a resolved target that is not a regular file. The
// container controls what sits at the path, and opening a FIFO for the ELF
// parse blocks until a writer appears, wedging the reconciler under its lock.
var errNotRegularFile = errors.New("not a regular file")

// errTargetTooLarge marks a resolved target too large to parse: the ELF read
// materializes sections in memory, so an implausibly large container-supplied
// binary is a memory-exhaustion vector.
var errTargetTooLarge = errors.New("target too large")

// maxTargetFileSize bounds a container-supplied binary we open: parsing its
// ELF (and hashing it for binaryDigests) materializes it in memory, so refuse
// an implausibly large target rather than trust what the container put there.
const maxTargetFileSize = 1 << 30 // 1 GiB

// checkTargetFile is the single rule for a container-supplied binary we are
// about to open: a regular file of a plausible size. what names the target in
// the error, since the resolver and the digest check report different paths.
func checkTargetFile(what string, regular bool, size int64) error {
	if !regular {
		return fmt.Errorf("%s is %w", what, errNotRegularFile)
	}
	if size > maxTargetFileSize {
		return fmt.Errorf("%s is %w: %d bytes (max %d)", what, errTargetTooLarge, size, maxTargetFileSize)
	}
	return nil
}

// checkResolvedTarget applies checkTargetFile to a resolved path. On the
// openat2 path that path is the inode-pinned "/proc/self/fd/<fd>", so the
// check cannot be raced by the container.
func checkResolvedTarget(path string) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fmt.Errorf("stat resolved path %q: %w", path, err)
	}
	return checkTargetFile(fmt.Sprintf("resolved path %q", path),
		st.Mode&unix.S_IFMT == unix.S_IFREG, int64(st.Size))
}

// resolveBinaryUnderRoot resolves path inside root and returns an attach path
// plus a cleanup to call only after the uprobe is attached (Relink() after the
// fd closes is a known gap). openat2(RESOLVE_IN_ROOT) confines symlinks/".."
// and returns an inode-pinned "/proc/self/fd/<fd>" closing the resolve->open
// TOCTOU window; falls back to a lexical <root>/<path> only when root is gone
// or openat2 is unsupported.
func resolveBinaryUnderRoot(root, path string) (string, func(), error) {
	noop := func() {}

	if path == "" {
		return "", noop, errors.New("empty path")
	}
	if root == "" {
		return "", noop, errors.New("empty container root")
	}

	resolved := filepath.Join(root, path)
	// Reject lexical ".." escapes; symlink escapes are handled by openat2.
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", noop, fmt.Errorf("path %q escapes container root", path)
	}

	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// Root genuinely gone, fall back to the lexical result. Nothing can
			// exist under a missing root, so there is no file to vet here: the
			// attach just fails with ENOENT and the container is retried.
			return resolved, noop, nil
		}
		// Fail closed on anything else: ENOTDIR means something that is not a
		// directory now sits at root, and falling back would drop symlink
		// containment on a possibly-live root.
		return "", noop, fmt.Errorf("opening container root %q: %w", root, err)
	}

	relClean := strings.TrimPrefix(filepath.Clean("/"+path), "/")
	if relClean == "" {
		unix.Close(dirfd)
		if err := checkResolvedTarget(resolved); err != nil {
			return "", noop, err
		}
		return resolved, noop, nil
	}

	how := &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC,
		// RESOLVE_IN_ROOT confines symlinks and ".."; RESOLVE_NO_MAGICLINKS
		// blocks container-planted magic links from redirecting the attach.
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := openat2(dirfd, relClean, how)
	unix.Close(dirfd)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
			openat2UnsupportedOnce.Do(func() {
				logger.GetLogger().Warn("uprobe resolvePathInContainer: kernel lacks openat2/RESOLVE_IN_ROOT; " +
					"resolving container paths without symlink containment (a container-controlled symlink " +
					"could redirect the attach outside the container). Kernel 5.6+ is required for containment.")
			})
			if err := checkResolvedTarget(resolved); err != nil {
				return "", noop, err
			}
			return resolved, noop, nil
		case errors.Is(err, unix.ENOENT):
			return "", noop, fmt.Errorf("path %q does not exist in container root: %w", path, err)
		default:
			return "", noop, fmt.Errorf("resolving %q in container root: %w", path, err)
		}
	}

	// Reject anything but a regular file before the caller opens it: a
	// container-planted FIFO would block the ELF/digest open forever.
	attachPath := procSelfFDPath(uintptr(fd))
	if err := checkResolvedTarget(attachPath); err != nil {
		unix.Close(fd)
		return "", noop, err
	}
	return attachPath, func() { unix.Close(fd) }, nil
}
