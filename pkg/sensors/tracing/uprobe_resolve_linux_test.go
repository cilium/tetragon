// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func requireOpenat2InRoot(t *testing.T) {
	t.Helper()
	if !hasOpenat2InRoot() {
		t.Skip("openat2(RESOLVE_IN_ROOT) not supported on this kernel")
	}
}

func stubNoContainment(t *testing.T) {
	t.Helper()
	orig := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = orig })
}

func TestResolveBinaryUnderRoot(t *testing.T) {
	requireOpenat2InRoot(t)

	root := filepath.Join(t.TempDir(), "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), []byte("x"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "lib", "real.so"), []byte("x"), 0o644))
	require.NoError(t, os.Symlink("/usr/lib/real.so", filepath.Join(root, "usr", "lib", "link.so")))
	require.NoError(t, os.Symlink("/etc/shadow", filepath.Join(root, "escape")))

	t.Run("regular file resolves to a pinned fd", func(t *testing.T) {
		f, st, err := resolveBinaryUnderRoot(root, "/usr/bin/app")
		require.NoError(t, err)
		defer f.Close()
		target, err := os.Readlink(procSelfFDPath(int(f.Fd())))
		require.NoError(t, err)
		require.Equal(t, filepath.Join(root, "usr", "bin", "app"), target)
		require.Equal(t, uint32(unix.S_IFREG), st.Mode&unix.S_IFMT)
	})

	t.Run("in-root symlink is allowed", func(t *testing.T) {
		f, _, err := resolveBinaryUnderRoot(root, "/usr/lib/link.so")
		require.NoError(t, err)
		f.Close()
	})

	t.Run("symlink escaping to the host is rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/escape")
		require.Error(t, err)
	})

	t.Run("dot-dot escape is rejected", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot(root, "/../../etc/shadow")
		require.Error(t, err)
	})

	t.Run("missing root is an error", func(t *testing.T) {
		_, _, err := resolveBinaryUnderRoot("/no/such/root", "/usr/bin/app")
		require.Error(t, err)
	})

	t.Run("non-directory root is an error", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
		_, _, err := resolveBinaryUnderRoot(file, "/usr/bin/app")
		require.Error(t, err)
	})

	t.Run("fifo is rejected", func(t *testing.T) {
		require.NoError(t, unix.Mkfifo(filepath.Join(root, "usr", "bin", "fifo"), 0o644))
		_, _, err := resolveBinaryUnderRoot(root, "/usr/bin/fifo")
		require.ErrorIs(t, err, errNotRegularFile)
	})

	t.Run("directory is rejected", func(t *testing.T) {
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

func TestResolveBinaryUnderRootRequiresContainment(t *testing.T) {
	stubNoContainment(t)
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "usr", "bin", "app"), []byte("x"), 0o755))

	_, _, err := resolveBinaryUnderRoot(root, "/usr/bin/app")
	require.ErrorIs(t, err, errNoContainment)
	require.False(t, hasOpenat2InRoot())
}
