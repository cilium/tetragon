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

// Test cgroup mode detection on an invalid directory
func TestDetectCgroupModeInvalid(t *testing.T) {
	mode, err := detectCgroupMode("invalid-cgroupfs-path")
	assert.Error(t, err)
	assert.Equal(t, CGROUP_UNDEF, mode)
}

// Test cgroup mode detection on default cgroup root /sys/fs/cgroup
func TestDetectCgroupModeDefault(t *testing.T) {
	var st syscall.Statfs_t

	err := syscall.Statfs(defaultCgroupRoot, &st)
	if err != nil {
		t.Skipf("TestDetectCgroupModeDefault() failed to Statfs(%s): %v, test skipped", defaultCgroupRoot, err)
	}

	mode, err := detectCgroupMode(defaultCgroupRoot)
	assert.NoError(t, err)

	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		assert.Equal(t, CGROUP_UNIFIED, mode)
	} else if st.Type == unix.TMPFS_MAGIC {
		unified := filepath.Join(defaultCgroupRoot, "unified")
		err = syscall.Statfs(unified, &st)
		if err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			assert.Equal(t, CGROUP_HYBRID, mode)

			// Extra detection
			mode, err = detectCgroupMode(unified)
			assert.NoError(t, err)
			assert.Equal(t, CGROUP_UNIFIED, mode)
		} else {
			assert.Equal(t, CGROUP_LEGACY, mode)
		}
	} else {
		t.Errorf("TestDetectCgroupModeDefault() failed Cgroupfs %s type failed:  want:%d or %d -  got:%d",
			defaultCgroupRoot, unix.CGROUP2_SUPER_MAGIC, unix.TMPFS_MAGIC, st.Type)
	}
}

// Test cgroup mode detection on our custom location /run/tetragon/cgroup2
func TestDetectCgroupModeCustomLocation(t *testing.T) {
	// We also mount cgroup2 on /run/tetragon/cgroup2 let's test it
	mounted, err := isDirMountFsType(defaults.Cgroup2Dir, mountinfo.FilesystemTypeCgroup2)
	assert.NoError(t, err)

	mode, err := detectCgroupMode(defaults.Cgroup2Dir)
	if mounted {
		assert.NoError(t, err)
		assert.Equal(t, CGROUP_UNIFIED, mode)
	} else {
		assert.Error(t, err)
		assert.Equal(t, CGROUP_UNDEF, mode)
	}
}

// Test cgroup mode detection. This will try to find the default
// location, perform the detection then asserts that corresponding
// variables 'cgroupMode' and 'cgroupFSPath' are properly set. These
// are set only once when we run the detection first time, further
// calls to DetectCgroupMode() will just return cgroupMode, so ensure
// they are properly set.
func TestDetectCgroupMode(t *testing.T) {
	mode, err := DetectCgroupMode()
	assert.NoError(t, err)
	assert.NotEqual(t, CGROUP_UNDEF, mode)
	assert.NotEqual(t, CGROUP_UNDEF, cgroupMode)
	assert.NotEmpty(t, cgroupFSPath)
}
