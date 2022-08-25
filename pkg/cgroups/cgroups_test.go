// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroups

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestDetectCgoupModeInvalid(t *testing.T) {
	mode, err := detectCgroupMode("invalid-cgroupfs-path")
	assert.Error(t, err)
	assert.Equal(t, CGROUP_UNDEF, mode)
}

func TestDetectCgoupModeSimple(t *testing.T) {
	mode, err := detectCgroupMode(defaultCgroupRoot)
	assert.NoError(t, err)

	var st syscall.Statfs_t
	err = syscall.Statfs(defaultCgroupRoot, &st)
	assert.NoError(t, err)

	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		assert.Equal(t, CGROUP_UNIFIED, mode)
	} else if st.Type == unix.TMPFS_MAGIC {
		unified := filepath.Join(defaultCgroupRoot, "unified")
		err = syscall.Statfs(unified, &st)
		if err != nil {
			mode, err = detectCgroupMode(unified)
			assert.Equal(t, CGROUP_LEGACY, mode)
		} else {
			assert.Equal(t, unix.CGROUP2_SUPER_MAGIC, st.Type)
			mode, err = detectCgroupMode(unified)
			assert.NoError(t, err)
			assert.Equal(t, CGROUP_HYBRID, mode)
		}
	} else {
		t.Errorf("detect Cgroupfs %s type failed:  want:%d or %d -  got:%d",
			defaultCgroupRoot, unix.CGROUP2_SUPER_MAGIC, unix.TMPFS_MAGIC, st.Type)
	}
}
