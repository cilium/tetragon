// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// trustTestDir returns a resolved temporary directory containing a bins directory with a binary
func trustTestDir(t *testing.T) (string, string) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(base, 0o755))
	bins := filepath.Join(base, "bins")
	require.NoError(t, os.Mkdir(bins, 0o755))
	require.NoError(t, os.Chmod(bins, 0o755))
	bin := filepath.Join(bins, "nop")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Chmod(bin, 0o755))
	return base, bins
}

func TestCheckTrustedBinsDir(t *testing.T) {
	// the temporary directory might be under a world-writable non-sticky directory
	base, _ := trustTestDir(t)
	if err := checkTrustedPath(base, getTrustedUIDs()); err != nil {
		// GitHub Actions sets CI=true: there the environment is known, so an untrusted temporary
		// directory means it changed and the trust checks would silently not run
		if os.Getenv("CI") == "true" {
			t.Fatalf("temporary directory is not trusted: %v", err)
		}
		t.Skipf("temporary directory is not trusted: %v", err)
	}

	t.Run("trusted", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Mkdir(filepath.Join(bins, "go"), 0o755))
		require.NoError(t, os.Symlink("nop", filepath.Join(bins, "nop-link")))
		require.NoError(t, checkTrustedBinsDir(bins))
	})

	t.Run("relative", func(t *testing.T) {
		require.ErrorContains(t, checkTrustedBinsDir("contrib/tester-progs"), "absolute")
	})

	t.Run("world-writable dir", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(bins, 0o777))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("sticky dir", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(bins, 0o777|os.ModeSticky))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("group-writable dir", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(bins, 0o775))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("world-writable parent", func(t *testing.T) {
		base, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(base, 0o777))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("sticky parent", func(t *testing.T) {
		base, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(base, 0o777|os.ModeSticky))
		require.NoError(t, checkTrustedBinsDir(bins))
	})

	t.Run("world-writable binary", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(filepath.Join(bins, "nop"), 0o757))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("group-writable binary", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chmod(filepath.Join(bins, "nop"), 0o775))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "writable by group or other")
	})

	t.Run("group-writable symlink target", func(t *testing.T) {
		base, bins := trustTestDir(t)
		target := filepath.Join(base, "target")
		require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755))
		require.NoError(t, os.Chmod(target, 0o775))
		require.NoError(t, os.Symlink(target, filepath.Join(bins, "link")))
		err := checkTrustedBinsDir(bins)
		require.ErrorContains(t, err, "writable by group or other")
		require.ErrorContains(t, err, filepath.Join(bins, "link")+" -> ")
	})

	t.Run("symlink to untrusted dir", func(t *testing.T) {
		base, bins := trustTestDir(t)
		other := filepath.Join(base, "other")
		require.NoError(t, os.Mkdir(other, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(other, "evil"), []byte("#!/bin/sh\n"), 0o755))
		require.NoError(t, os.Chmod(other, 0o777))
		require.NoError(t, os.Symlink(filepath.Join(other, "evil"), filepath.Join(bins, "evil")))
		err := checkTrustedBinsDir(bins)
		require.ErrorContains(t, err, "writable by group or other")
		require.ErrorContains(t, err, filepath.Join(bins, "evil")+" -> ")
	})

	t.Run("symlink in path", func(t *testing.T) {
		base, bins := trustTestDir(t)
		link := filepath.Join(base, "bins-link")
		require.NoError(t, os.Symlink(bins, link))
		require.ErrorContains(t, checkTrustedBinsDir(link), "is not a directory")
	})

	t.Run("dangling symlink", func(t *testing.T) {
		_, bins := trustTestDir(t)
		require.NoError(t, os.Symlink("missing", filepath.Join(bins, "missing-link")))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "failed to resolve")
	})

	t.Run("invoking user", func(t *testing.T) {
		t.Setenv("SUDO_UID", "1234")
		want := uint32(os.Geteuid())
		if want == 0 {
			want = 1234
		}
		require.Equal(t, []uint32{0, want}, getTrustedUIDs())
	})

	t.Run("untrusted owner", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing file ownership requires root")
		}
		t.Setenv("SUDO_UID", "")
		_, bins := trustTestDir(t)
		require.NoError(t, os.Chown(filepath.Join(bins, "nop"), 65534, 65534))
		require.ErrorContains(t, checkTrustedBinsDir(bins), "not owned by trusted uid")
	})
}
