// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// NB: there is an import cycle that does allow us to use testutils.RepoRootPath
func repoRootPath() string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..")
}

func initBpffs() string {
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	dirPath, err := os.MkdirTemp(defaults.DefaultMapRoot, "test-cgtracker-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup bpf map root: %s\n", err)
		return ""
	}
	dir := filepath.Base(dirPath)
	bpf.SetMapPrefix(dir)
	return dirPath
}

func TestMain(m *testing.M) {
	flag.StringVar(&option.Config.HubbleLib,
		"bpf-lib", filepath.Join(repoRootPath(), "bpf", "objs"),
		"tetragon lib directory (location of btf file and bpf objs).")
	flag.Parse()

	if envLib := os.Getenv("TETRAGON_LIB"); envLib != "" {
		option.Config.HubbleLib = envLib
	}

	err := btf.InitCachedBTF(defaults.DefaultTetragonLib, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing BTF file: %s", err)
		os.Exit(1)
	}

	// setup a custom bpffs path to pin objects
	dirPath := initBpffs()
	defer func() {
		// cleanup bpffs path
		if dirPath != "" {
			os.RemoveAll(dirPath)
		}
	}()

	ec := m.Run()

	os.Exit(ec)
}

// dummy sesnor for testing
func loadCgTrackerSensor(t *testing.T) *sensors.Sensor {
	s := &sensors.Sensor{
		Name:  "cgtracker_test",
		Progs: nil,
		Maps:  nil,
	}
	var err error
	s, err = RegisterCgroupTracker(s)
	require.NoError(t, err)
	tus.LoadSensor(t, s)
	return s
}

func doMapTest(t *testing.T, cgfsPath string) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(cgfsPath, &st); err != nil {
		t.Fatalf("error accessing cgroup path '%s': %s", cgfsPath, err)
	}
	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		t.Logf("'%s' is cgroup v2", cgfsPath)
	} else if st.Type == unix.TMPFS_MAGIC {
		t.Logf("'%s' is cgroup v1", cgfsPath)
	}

	// create tempdir
	dir, err := os.MkdirTemp(cgfsPath, "cgtracker-test-*")
	if err != nil {
		t.Fatalf("failed to create test dir: %s", err)
	}
	t.Cleanup(func() {
		err := os.RemoveAll(dir)
		if err != nil {
			t.Logf("failed to remove '%s': %s", dir, err)
		}
	})
	t.Logf("created cgroup dir '%s'", dir)

	cgPaths := []string{"untracked", "untracked/a", "tracked", "tracked/a", "tracked/a/x1", "tracked/a/x2", "tracked/b"}
	// create a directory inside this tempdir
	for _, d := range cgPaths {
		d = filepath.Join(dir, d)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatalf("failed to create '%s': %s", d, err)
		}
	}

	fname := filepath.Join(bpf.MapPrefixPath(), MapName)
	m, err := OpenMap(fname)
	if err != nil {
		t.Fatalf("failed to open cgtracker map: %s", err)
	}
	defer m.Close()

	err = m.AddCgroupTrackerPath(filepath.Join(dir, "tracked"))
	require.NoError(t, err)
	trackerID, err := cgroups.GetCgroupIdFromPath(filepath.Join(dir, "tracked"))
	require.NoError(t, err)

	for _, path := range cgPaths {
		if !strings.HasPrefix(path, "tracked") {
			continue
		}
		cgPath := filepath.Join(dir, path)
		trackedID, err := cgroups.GetCgroupIdFromPath(cgPath)
		require.NoError(t, err)
		var val uint64
		err = m.Lookup(&trackedID, &val)
		require.NoError(t, err)
		require.Equal(t, trackerID, val)
	}

	cgPaths2 := []string{"untracked/b", "tracked/c", "tracked/a/z", "tracked/c/y"}
	for _, path := range cgPaths2 {
		cgPath := filepath.Join(dir, path)
		if err := os.Mkdir(cgPath, 0700); err != nil {
			t.Fatalf("failed to create '%s': %s", cgPath, err)
		}
		trackedID, err := cgroups.GetCgroupIdFromPath(cgPath)
		require.NoError(t, err)
		var val uint64
		err = m.Lookup(&trackedID, &val)
		if strings.HasPrefix(path, "tracked") {
			assert.NoError(t, err, fmt.Sprintf("cgroup (%x) id for %s should exist in the map", trackedID, cgPath))
			assert.Equal(t, trackerID, val, fmt.Sprintf("tracker ID value should match tracker for key 0x%x (%s)", trackedID, cgPath))
		} else {
			assert.Error(t, err)
		}
	}

	for _, path := range slices.Backward(slices.Concat(cgPaths, cgPaths2)) {
		cgPath := filepath.Join(dir, path)
		if err := os.Remove(cgPath); err != nil {
			t.Fatalf("failed to unlink '%s': %s", cgPath, err)
		}
	}

	// NB(kkourt): We use sleep here because cgtracker hooks into _release() not _rmdir() which
	// runs under kworker and executed after the rmdirs() are completed.
	time.Sleep(1 * time.Second)
	vals, err := m.Dump()
	require.NoError(t, err)
	assert.Equal(t, vals, map[uint64][]uint64{})
}

func TestCgTrackerMap(t *testing.T) {
	loadCgTrackerSensor(t)
	doMapTest(t, "/sys/fs/cgroup")
}
