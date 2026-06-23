// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openat2Supported reports whether the kernel supports openat2 with
// RESOLVE_IN_ROOT, so the containment test can skip on older kernels where
// resolveBinaryUnderRoot falls back to the lexical check.
func openat2Supported(t *testing.T) bool {
	t.Helper()
	fd, err := unix.Openat2(unix.AT_FDCWD, ".",
		&unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// resolveBinaryUnderRoot confines symlinks and ".." to the container root via
// openat2(RESOLVE_IN_ROOT), so a container-controlled symlink cannot redirect
// the agent to a host file.
func TestResolveBinaryUnderRoot(t *testing.T) {
	if !openat2Supported(t) {
		t.Skip("openat2(RESOLVE_IN_ROOT) not supported on this kernel")
	}

	const hostPID = 1
	procFS := t.TempDir()
	root := filepath.Join(procFS, strconv.Itoa(hostPID), "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), []byte("x"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "lib", "real.so"), []byte("x"), 0o644))

	// in-root symlink (libpam.so.0 -> libpam.so.0.85.1 style) must resolve.
	require.NoError(t, os.Symlink("/usr/lib/real.so", filepath.Join(root, "usr", "lib", "link.so")))
	// absolute symlink pointing at a host file: with RESOLVE_IN_ROOT it is
	// confined to the container root, where the target does not exist.
	require.NoError(t, os.Symlink("/etc/shadow", filepath.Join(root, "escape")))

	t.Run("regular file resolves to a pinned fd path", func(t *testing.T) {
		got, closeFn, err := resolveBinaryUnderRoot(root, "/usr/bin/app")
		require.NoError(t, err)
		defer closeFn()
		require.True(t, strings.HasPrefix(got, "/proc/self/fd/"), "expected fd-pinned path, got %q", got)
	})

	t.Run("in-root symlink is allowed", func(t *testing.T) {
		_, closeFn, err := resolveBinaryUnderRoot(root, "/usr/lib/link.so")
		require.NoError(t, err)
		closeFn()
	})

	t.Run("symlink escaping to host is contained and rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/escape")
		require.Error(t, err, "an escaping symlink must not resolve to the host file")
	})

	t.Run("lexical .. escape is rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/../../etc/shadow")
		require.Error(t, err)
	})

	t.Run("non-openable root falls back to the lexical path", func(t *testing.T) {
		got, closeFn, err := resolveBinaryUnderRoot("/no/such/root", "/usr/bin/bash")
		require.NoError(t, err)
		closeFn()
		require.Equal(t, "/no/such/root/usr/bin/bash", got)
	})

	t.Run("empty path and empty root are rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "")
		require.Error(t, err)
		_, _, err = resolveBinaryUnderRoot("", "/usr/bin/bash")
		require.Error(t, err)
	})
}
