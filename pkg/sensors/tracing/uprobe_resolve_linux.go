// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
)

// openat2UnsupportedOnce rate-limits the warning emitted when the kernel lacks
// openat2/RESOLVE_IN_ROOT and resolution downgrades to the symlink-unsafe
// lexical fallback. openat2 support is a kernel-global property, so warning once
// per agent is sufficient and avoids per-container/per-resync spam.
var openat2UnsupportedOnce sync.Once

// resolveBinaryUnderRoot resolves path inside the container root directory and
// returns a path the agent can hand to the uprobe loader, plus a cleanup
// function the caller must call once the uprobe has been attached. root is a
// directory the agent can open that is the container's root filesystem (a
// runtime-hook RootDir or a CRI-reported <procFS>/<pid>/root).
//
// When root is openable and the kernel supports openat2, it resolves path with
// RESOLVE_IN_ROOT — which confines symlinks and ".." to the container root, so a
// container-controlled symlink cannot redirect the agent to a host file — and
// returns "/proc/self/fd/<fd>" referring to the opened (inode-pinned) file.
// Keeping the fd open until after the attach also closes the resolve->open
// TOCTOU window for the duration of the load.
//
// When root cannot be opened (e.g. the process has exited, or in unit tests with
// a synthetic root) or openat2/RESOLVE_IN_ROOT is unsupported (kernel < 5.6), it
// falls back to a lexical <root>/<path> that only guards against ".." escapes.
//
// Known residual gap: the caller must close the returned fd only after the
// uprobe is attached; a later Relink() of the sensor would re-resolve the
// "/proc/self/fd/N" path after the fd is gone.
func resolveBinaryUnderRoot(root, path string) (string, func(), error) {
	noop := func() {}

	if path == "" {
		return "", noop, errors.New("empty path")
	}
	if root == "" {
		return "", noop, errors.New("empty container root")
	}

	resolved := filepath.Join(root, path)
	// filepath.Join cleans the result, so a path containing ".." that escapes
	// the container root resolves outside of root; reject it via a relative-path
	// check (robust to trailing/duplicate separators in root, unlike a raw prefix
	// compare). This only catches lexical ".." escapes, not symlink escapes (the
	// openat2 path below does).
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", noop, fmt.Errorf("path %q escapes container root", path)
	}

	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		// Root not openable here (process gone, no host-fs access for an overlay
		// RootDir, or synthetic root in tests): fall back to the lexical result.
		return resolved, noop, nil
	}

	relClean := strings.TrimPrefix(filepath.Clean("/"+path), "/")
	if relClean == "" {
		unix.Close(dirfd)
		return resolved, noop, nil
	}

	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	}
	fd, err := unix.Openat2(dirfd, relClean, how)
	unix.Close(dirfd)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
			// openat2 or RESOLVE_IN_ROOT genuinely unsupported (old kernel):
			// cannot harden, fall back to the lexical result. EPERM is NOT
			// included here: on a kernel that supports openat2 it signals a real
			// access failure, and silently downgrading to the symlink-unsafe
			// lexical path would defeat the containment guarantee, so reject it.
			//
			// Warn once: on such a kernel the per-container uprobe attaches
			// without the symlink-containment guarantee the docs advertise, so a
			// container-controlled symlink at path could redirect the attach to a
			// host file. Operators need this visible to assess the risk.
			openat2UnsupportedOnce.Do(func() {
				logger.GetLogger().Warn("uprobe resolvePathInContainer: kernel lacks openat2/RESOLVE_IN_ROOT; " +
					"resolving container paths without symlink containment (a container-controlled symlink " +
					"could redirect the attach outside the container). Kernel 5.6+ is required for containment.")
			})
			return resolved, noop, nil
		case errors.Is(err, unix.ENOENT):
			return "", noop, fmt.Errorf("path %q does not exist in container root: %w", path, err)
		default:
			return "", noop, fmt.Errorf("resolving %q in container root: %w", path, err)
		}
	}

	attachPath := "/proc/self/fd/" + strconv.Itoa(fd)
	return attachPath, func() { unix.Close(fd) }, nil
}
