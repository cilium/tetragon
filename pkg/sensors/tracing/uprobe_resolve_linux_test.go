// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestResolveBinaryUnderRoot(t *testing.T) {
	if !hasOpenat2InRoot() {
		t.Skip("openat2(RESOLVE_IN_ROOT) not supported on this kernel")
	}

	root := filepath.Join(t.TempDir(), "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), []byte("x"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "lib", "real.so"), []byte("x"), 0o644))

	// in-root symlink (libpam.so.0 -> libpam.so.0.85.1 style) must resolve.
	require.NoError(t, os.Symlink("/usr/lib/real.so", filepath.Join(root, "usr", "lib", "link.so")))
	// absolute symlink pointing at a host file: RESOLVE_IN_ROOT confines it to
	// the container root, where the target does not exist.
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

	t.Run("symlink escaping to the host is contained and rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/escape")
		require.Error(t, err, "an escaping symlink must not resolve to the host file")
	})

	t.Run("dot-dot escape is contained and rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/../../etc/shadow")
		require.Error(t, err)
	})

	t.Run("missing root is an error", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot("/no/such/root", "/usr/bin/app")
		require.Error(t, err, "a vanished root must not resolve to anything")
	})

	t.Run("non-directory root is an error", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
		_, _, err := resolveBinaryUnderRoot(file, "/usr/bin/app")
		require.Error(t, err)
	})

	t.Run("non-regular file is rejected", func(t *testing.T) {
		require.NoError(t, unix.Mkfifo(filepath.Join(root, "usr", "bin", "fifo"), 0o644))
		_, _, err := resolveBinaryUnderRoot(root, "/usr/bin/fifo")
		require.ErrorIs(t, err, errNotRegularFile,
			"opening a container-planted FIFO would block the ELF read and wedge the reconciler")
	})

	t.Run("directory target is rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/usr/bin")
		require.ErrorIs(t, err, errNotRegularFile)
	})

	t.Run("empty path and empty root are rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "")
		require.Error(t, err)
		_, _, err = resolveBinaryUnderRoot("", "/usr/bin/app")
		require.Error(t, err)
	})
}

// Policy load refuses a kernel without containment, so resolution never falls
// back to an uncontained join.
func TestResolveBinaryUnderRootRequiresContainment(t *testing.T) {
	openat2Orig := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { openat2 = openat2Orig })

	// The target exists and a plain join would find it: refusing anyway is the
	// property under test.
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), []byte("x"), 0o755))

	_, _, err := resolveBinaryUnderRoot(root, "/usr/bin/app")
	require.ErrorIs(t, err, errNoContainment)
	require.False(t, hasOpenat2InRoot())
}
