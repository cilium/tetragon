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

func TestResolveBinaryUnderRoot(t *testing.T) {
	requireOpenat2InRoot(t)
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	root := filepath.Join(base, "root")
	require.NoError(t, os.WriteFile(outside, []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "lib", "real.so"), []byte("x"), 0o644))
	require.NoError(t, os.Symlink("/lib/real.so", filepath.Join(root, "lib", "link.so")))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))
	require.NoError(t, unix.Mkfifo(filepath.Join(root, "fifo"), 0o644))

	f, _, err := resolveBinaryUnderRoot(root, "/lib/link.so")
	require.NoError(t, err)
	defer f.Close()
	target, err := os.Readlink(procSelfFDPath(int(f.Fd())))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "lib", "real.so"), target)

	for _, path := range []string{"/escape", "/../outside"} {
		_, _, err = resolveBinaryUnderRoot(root, path)
		require.ErrorIs(t, err, unix.ENOENT, path)
	}

	_, _, err = resolveBinaryUnderRoot(root, "/fifo")
	require.ErrorIs(t, err, errNotRegularFile)
}
