// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/mountinfo"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func isDirMountFsType(path string, mntType string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, nil
	}

	if !st.IsDir() {
		return false, fmt.Errorf("%s is not a directory", path)
	}

	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return false, err
	}

	mounted, instance := mountinfo.IsMountFS(infos, mntType, path)
	if !mounted {
		return false, fmt.Errorf("%s directory exists but not mounted as %s! left-over?", path, mntType)
	}

	if !instance {
		return false, fmt.Errorf("%s has different mount system than %s", path, mntType)
	}

	return true, nil
}

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

func TestDetectCgroupModeInvalid(t *testing.T) {
	defaultCgroupRoot = "invalid-cgroupfs-path"

	// In case we have /run/tetragon/cgroup2 mounted we fallback to it
	mounted, err := isDirMountFsType(defaults.Cgroup2Dir, mountinfo.FilesystemTypeCgroup2)
	assert.NoError(t, err)
	mode, err := DetectCgroupMode()

	if mounted {
		assert.NoError(t, err)
		assert.Equal(t, CGROUP_UNIFIED, mode)
		assert.Equal(t, CGROUP_UNIFIED, cgroupMode)

		// Ensure that cgroupFSPath is set
		assert.Equal(t, defaults.Cgroup2Dir, cgroupFSPath)
	} else {
		assert.Error(t, err)
		assert.Equal(t, CGROUP_UNDEF, mode)
		assert.Equal(t, CGROUP_UNDEF, cgroupMode)
	}
}

func TestDetectCgroupModeDefault(t *testing.T) {
	mode, err := DetectCgroupMode()
	assert.NoError(t, err)
	assert.NotEqual(t, CGROUP_UNDEF, mode)
	assert.NotEqual(t, CGROUP_UNDEF, cgroupMode)
}
