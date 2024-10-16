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
	"github.com/stretchr/testify/require"
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

func TestParseCgroupSubSysIds(t *testing.T) {

	testDir := t.TempDir()

	d := struct {
		used string
		data string
	}{"memory,cpuset",
		`
#subsys_name	hierarchy	num_cgroups	enabled
cpuset	7	2	1
cpu	6	78	1
cpuacct	6	78	1
blkio	4	78	1
memory	13	106	1
devices	11	81	1
freezer	5	5	1
net_cls	2	2	1
perf_event	8	2	1
net_prio	2	2	1
hugetlb	12	2	1
rdma	9	2	1
misc	10	1	1
`}

	file := filepath.Join(testDir, "testfile")
	err := os.WriteFile(file, []byte(d.data), 0644)
	require.NoError(t, err)

	err = parseCgroupSubSysIds(file)
	require.NoError(t, err)
	for _, c := range CgroupControllers {
		if strings.Contains(d.used, c.Name) {
			require.Equal(t, true, c.Active)
			require.NotZero(t, c.Id)
		} else {
			require.Equal(t, false, c.Active)
			require.Zero(t, c.Id)
		}
	}
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

	cgroup, err := NewCGroups()
	assert.NoError(t, err)
	assert.NotEmpty(t, cgroup.Path())
	assert.NotZero(t, cgroup.Mode())
	assert.NotZero(t, cgroup.FSMagic())
}

// Test cgroup FS magic detection. This will run DetectCgroupFSMagic()
// ensures that we properly get the cgroup filesystem magic number
// but also the cgroupMode is properly set, since DetectCgroupFSMagic()
// will automatically call DetectCgroupMode().
//
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

	assert.NotEmpty(t, CgroupFsMagicStr(fs))

	cgroup, err := NewCGroups()
	assert.NoError(t, err)
	assert.NotZero(t, cgroup.Mode())
	assert.NotEqual(t, uint64(CGROUP_UNDEF), cgroup.FSMagic())
	assert.NotEmpty(t, cgroup.Path())
	assert.Equal(t, true, filepath.IsAbs(cgroup.Path()))
}

// Test discovery of compiled-in Cgroups controllers
// This will ensure that:
// - We properly discover compiled-in cgroup controllers
// - Their hierarchy IDs
// - Their css index
func TestDiscoverSubSysIdsDefault(t *testing.T) {
	fs, err := DetectCgroupFSMagic()
	assert.NoError(t, err)
	assert.NotEqual(t, CGROUP_UNDEF, fs)

	err = DiscoverSubSysIds()
	assert.NoError(t, err)

	accessFs := false
	fixed := false
	var st syscall.Statfs_t
	err = syscall.Statfs(defaultCgroupRoot, &st)
	if err == nil {
		accessFs = true
	}
	for _, controller := range CgroupControllers {
		if accessFs {
			if cgroupMode == CGROUP_UNIFIED {
				assert.EqualValues(t, 0, controller.Id, "Cgroupv2 Controller '%s' hierarchy ID should be O as it is Unified Cgroup", controller.Name)
			} else {
				assert.NotEqualValues(t, 0, controller.Id, "Cgroupv1 Controller '%s' hierarchy ID should not be zero", controller.Name)
			}
		}

		if controller.Active {
			fixed = true

			// If those controllers are active let's check their css index
			if controller.Name == "memory" || controller.Name == "pids" {
				assert.NotEqualValues(t, 0, controller.Idx, "Cgroup Controller '%s' css index should not be zero", controller.Name)
			}
		}
	}

	assert.Equalf(t, true, fixed, "TestDiscoverSubSysIdsDefault() could not detect and fix compiled Cgroup controllers")

	cgroup, err := NewCGroups()
	assert.NoError(t, err)
	controllers, err := cgroup.Controllers()
	assert.NoError(t, err)
	count := 0
	for _, controller := range controllers {
		if controller.Active {
			count++
		}
	}

	assert.NotZero(t, count)

	cgroup.LogState()
}

func TestGetCgroupIdFromPath(t *testing.T) {
	mode, err := DetectCgroupMode()
	assert.NoError(t, err)
	assert.NotEqual(t, CGROUP_UNDEF, mode)

	err = DiscoverSubSysIds()
	assert.NoError(t, err)

	pid := os.Getpid()
	path, err := findMigrationPath(uint32(pid))
	assert.NoError(t, err)
	assert.NotEmpty(t, path)

	id, err := GetCgroupIdFromPath(path)
	assert.NoError(t, err)
	assert.NotZero(t, id)

	// Log data useful to inspect different hierarchies
	t.Logf("\ncgroup.Path=%s cgroup.ID=%d\n", path, id)
}

func TestPidCgroupEnv(t *testing.T) {
	cgroup, err := NewCGroups()
	assert.NoError(t, err)

	pid := os.Getpid()
	err = cgroup.DetectPidCgroupEnv(uint32(pid))
	assert.NoError(t, err)

	path, err := cgroup.GetPidCgroupPath()
	assert.NoError(t, err)
	assert.NotEmpty(t, path)

	_, err = cgroup.GetPidHierarchyId()
	assert.NoError(t, err)

	_, err = cgroup.GetPidControllerIdx()
	assert.NoError(t, err)

	name, err := cgroup.GetPidControllerName()
	assert.NoError(t, err)
	assert.NotEmpty(t, name)

	cgroup.LogState()
}
