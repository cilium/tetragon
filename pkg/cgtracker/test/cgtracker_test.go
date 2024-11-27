// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgtracker"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	_ "github.com/cilium/tetragon/pkg/sensors/exec" // NB: needed so that the exec sensor can load the execve probe on its init
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	testprogs "github.com/cilium/tetragon/pkg/testutils/progs"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "cgtracker-test")
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

	oldVal := option.Config.EnableCgTrackerID
	option.Config.EnableCgTrackerID = true
	t.Cleanup(func() {
		option.Config.EnableCgTrackerID = oldVal
	})

	s, err = cgtracker.RegisterCgroupTracker(s)
	require.NoError(t, err)
	tus.LoadSensor(t, s)
	return s
}

func cgfsMkdirTemp(t *testing.T, cgfsPath string) string {
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
	return dir
}

func doMapTest(t *testing.T, cgfsPath string) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	dir := cgfsMkdirTemp(t, cgfsPath)
	t.Logf("created cgroup dir '%s'", dir)

	cgPaths := []string{"untracked", "untracked/a", "tracked", "tracked/a", "tracked/a/x1", "tracked/a/x2", "tracked/b"}
	// create a directory inside this tempdir
	for _, d := range cgPaths {
		d = filepath.Join(dir, d)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatalf("failed to create '%s': %s", d, err)
		}
	}

	fname := filepath.Join(bpf.MapPrefixPath(), cgtracker.MapName)
	m, err := cgtracker.OpenMap(fname)
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

func loadExecSensorWithCgTracker(t *testing.T) {
	oldVal := option.Config.EnableCgTrackerID
	option.Config.EnableCgTrackerID = true
	t.Cleanup(func() {
		option.Config.EnableCgTrackerID = oldVal
	})
	tus.LoadInitialSensor(t)
	tus.LoadSensor(t, testsensor.GetTestSensor())
}

func TestCgTrackerEvents(t *testing.T) {
	doProgTest(t, "/sys/fs/cgroup")
}

func doProgTest(t *testing.T, cgfsPath string) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	dir := cgfsMkdirTemp(t, cgfsPath)
	t.Logf("created cgroup dir '%s'", dir)

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}
	err := confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	require.NoError(t, err)

	loadExecSensorWithCgTracker(t)

	fname := filepath.Join(bpf.MapPrefixPath(), cgtracker.MapName)
	m, err := cgtracker.OpenMap(fname)
	if err != nil {
		t.Fatalf("failed to open cgtracker map '%s': %s", fname, err)
	}
	defer m.Close()

	cgPaths := []string{"a", "b", "a/x"}
	cgIDs := map[string]uint64{}
	fullPath := map[string]string{}
	for _, path := range cgPaths {
		d := filepath.Join(dir, path)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatalf("failed to create '%s': %s", d, err)
		}
		if path == "a" {
			err = m.AddCgroupTrackerPath(d)
			require.NoError(t, err)
		}

		cgID, err := cgroups.GetCgroupIdFromPath(d)
		require.NoError(t, err)
		cgIDs[path] = cgID
		t.Logf("cgid for %s is %d", path, cgID)
		fullPath[path] = d
	}
	t.Cleanup(func() {
		for _, path := range slices.Backward(cgPaths) {
			cgPath := filepath.Join(dir, path)
			i := 0
			for {
				if err := os.Remove(cgPath); err == nil {
					break
				} else if i == 5 {
					t.Logf("failed to unlink '%s': %s", cgPath, err)
					break
				}
				time.Sleep(10 * time.Millisecond)
				i++
			}
		}
	})

	// copy command /bin/true to /tmp so that we can effectively filter based on binary
	tmpTrue := testutils.CopyExecToTemp(t, "true")
	progTester := testprogs.StartTester(t, context.Background())

	type testCase struct {
		cgPath         string // cgroup path
		expCgID        uint64 // expected cgroup id
		expCgTrackerID uint64 // expetect cgroup tracker id
	}

	tcs := []testCase{
		{cgPath: "a", expCgID: cgIDs["a"], expCgTrackerID: cgIDs["a"]},
		{cgPath: "a/x", expCgID: cgIDs["a/x"], expCgTrackerID: cgIDs["a"]},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, tc := range tcs {
		// add tester to the specified cgroup
		progTester.AddToCgroup(t, fullPath[tc.cgPath])

		// print cgroup to logs
		out, err := progTester.Command("exec /usr/bin/cat /proc/self/cgroup")
		require.NoError(t, err, out)
		t.Logf("%s", out)

		// for the test operation, we execute a copy of "true" to generate an exec event
		ops := func() {
			if out, err := progTester.Exec(tmpTrue); err != nil {
				t.Logf("command failed: %s", err)
			} else {
				t.Logf("ops out: %s", out)
			}
		}

		// run the op and check the events
		events := perfring.RunTestEvents(t, ctx, ops)
		for _, ev := range events {
			if exec, ok := ev.(*grpcexec.MsgExecveEventUnix); ok {
				if exec.Unix.Process.Filename == tmpTrue {
					require.Equal(t, tc.expCgID, exec.Unix.Kube.Cgrpid, "cgroup id does not match")
					require.Equal(t, tc.expCgTrackerID, exec.Unix.Kube.CgrpTrackerID, "cgroup tracker id does not match")
				}
			}
		}
	}

	progTester.Stop()
}
