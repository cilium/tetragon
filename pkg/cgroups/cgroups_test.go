// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestCgroupNameFromCStr(t *testing.T) {
	type progTest struct {
		in   []byte
		want string
	}

	containerId := "docker-713516e64fa59fc6c7216b29b25d395a606083232bdaf07e53540cd8252ea3f7.scope"
	cgroupPath := "/system.slice/docker-713516e64fa59fc6c7216b29b25d395a606083232bdaf07e53540cd8252ea3f7.scope"
	bempty := []byte{0x00}
	emptycontainerId := []byte(containerId)
	emptycontainerId[0] = 0x00
	bcontainerId := []byte(containerId)
	cidx := strings.Index(containerId, "6e")
	bcontainerId[cidx] = 0x00
	pidx := strings.LastIndex(cgroupPath, "/")
	bcgroupPath := []byte(cgroupPath)
	bcgroupPath[pidx] = 0x00

	testcases := []progTest{
		{
			in:   []byte(""),
			want: "",
		},
		{
			in:   bempty,
			want: "",
		},
		{
			in:   emptycontainerId,
			want: "",
		},
		{
			in:   []byte(containerId),
			want: containerId,
		},
		{
			in:   []byte(cgroupPath),
			want: cgroupPath,
		},
		{
			in:   bcontainerId,
			want: containerId[:cidx],
		},
		{
			in:   bcgroupPath,
			want: "/system.slice",
		},
	}

	for _, test := range testcases {
		out := CgroupNameFromCStr(test.in)
		if out != test.want {
			t.Errorf("CgroupNameFromCStr() mismatch - want:'%s'  -  got:'%s'\n", test.want, out)
		}
	}
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

// TODO Setup multiple cgroupv1 and cgroupv2 combinations
func TestDetectCgroupFSMagic(t *testing.T) {
	fs, err := DetectCgroupFSMagic()
	assert.NoError(t, err)
	assert.NotEqual(t, CGROUP_UNDEF, fs)
	if cgroupMode == CGROUP_UNIFIED {
		assert.Equal(t, uint64(unix.CGROUP2_SUPER_MAGIC), fs)
	} else if cgroupMode == CGROUP_HYBRID {
		assert.Equal(t, uint64(unix.CGROUP_SUPER_MAGIC), fs)
		mounted, err := isDirMountFsType(filepath.Join(cgroupFSPath, "unified"), mountinfo.FilesystemTypeCgroup2)
		assert.NoError(t, err)
		assert.Equal(t, true, mounted)
	} else if cgroupMode == CGROUP_LEGACY {
		assert.Equal(t, uint64(unix.CGROUP_SUPER_MAGIC), fs)
	} else {
		t.Errorf("Test failed to get Cgroup filesystem %s type", cgroupFSPath)
	}
}

func TestDetectCgroupFSMagicVariant(t *testing.T) {
	mounted, err := isDirMountFsType(defaults.Cgroup2Dir, mountinfo.FilesystemTypeCgroup2)
	assert.NoError(t, err)

	fs, err := DetectCgroupFSMagic()
	assert.NoError(t, err)

	if mounted {
		assert.NoError(t, err)
		assert.Equal(t, CGROUP_UNIFIED, cgroupMode)
		assert.Equal(t, uint64(unix.CGROUP2_SUPER_MAGIC), fs)
	} else {
		// Fallback to default
		assert.NoError(t, err)
		assert.NotEqual(t, CGROUP_UNDEF, fs)
		assert.NotEqual(t, CGROUP_UNDEF, cgroupMode)
	}
}
