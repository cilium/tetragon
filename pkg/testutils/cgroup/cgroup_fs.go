// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgroup

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// cgfsMkdirTemp creates a temp directory under the provided cgroup fs mountpoint
func CgfsMkTemp(t *testing.T, cgfsPath string, pattern string) string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(cgfsPath, &st); err != nil {
		t.Fatalf("error accessing cgroup path '%s': %s", cgfsPath, err)
	}
	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		t.Logf("'%s' is cgroup v2", cgfsPath)
	} else if st.Type == unix.TMPFS_MAGIC {
		t.Logf("'%s' is cgroup v1", cgfsPath)
	} else {
		t.Fatalf("'%s' not a cgroup fs", cgfsPath)
	}

	// create tempdir
	dir, err := os.MkdirTemp(cgfsPath, pattern)
	if err != nil {
		t.Skipf("skipping test, failed to create test dir: %s", err)
	}
	t.Cleanup(func() {
		err := os.Remove(dir)
		if err != nil {
			t.Logf("failed to remove '%s': %s", dir, err)
		}
	})
	return dir
}
