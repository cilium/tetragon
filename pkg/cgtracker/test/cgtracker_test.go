// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"context"
	"fmt"
	"iter"
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
		t.Skipf("skipping test, failed to create test dir: %s", err)
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

	cgfs := newTestCgroupFS(t, cgfsPath)

	// create cgroup directories
	dontTrack := func(_ string) bool { return false }
	cgPaths := []string{"untracked", "untracked/a", "tracked", "tracked/a", "tracked/a/x1", "tracked/a/x2", "tracked/b"}
	cgfs.mkdirs(t, cgPaths, dontTrack)

	// add "tracked" directory
	err := cgfs.cgTrackerMap.AddCgroupTrackerPath(cgfs.fullpath("tracked"))
	require.NoError(t, err)
	trackerID := cgfs.cgIDs["tracked"]

	// check that AddCgroupTrackerPath call above added all directories under "tracked"
	for _, path := range cgPaths {
		if !strings.HasPrefix(path, "tracked") {
			continue
		}
		trackedID := cgfs.cgIDs[path]
		var val uint64
		err = cgfs.cgTrackerMap.Lookup(&trackedID, &val)
		require.NoError(t, err)
		require.Equal(t, trackerID, val)
	}

	// add more directories and check that they are properly tracked
	cgPaths2 := []string{"untracked/b", "tracked/c", "tracked/a/z", "tracked/c/y"}
	cgfs.mkdirsCheck(t, cgPaths2, dontTrack, func(t *testing.T, fs *testCgroupFS, p string) {
		trackedID := fs.cgIDs[p]
		var val uint64
		err = fs.cgTrackerMap.Lookup(&trackedID, &val)
		if strings.HasPrefix(p, "tracked") {
			assert.NoError(t, err, fmt.Sprintf("cgroup (%x) id for %s should exist in the map", trackedID, p))
			assert.Equal(t, trackerID, val, fmt.Sprintf("tracker ID value should match tracker for key 0x%x (%s)", trackedID, p))
		} else {
			assert.Error(t, err)
		}

	})

	// remove all directories
	cgfs.rmAllDirs(t)

	// NB(kkourt): We use sleep here because cgtracker hooks into _release() not _rmdir() which
	// runs under kworker and executed after the rmdirs() are completed.
	time.Sleep(1 * time.Second)
	vals, err := cgfs.cgTrackerMap.Dump()
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

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}
	err := confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	require.NoError(t, err)

	loadExecSensorWithCgTracker(t)
	cgfs := newTestCgroupFS(t, cgfsPath)

	// create directories, and track path "a"
	// NB: the sensor is already loaded so "a/x" should end up being tracked as well
	cgfs.mkdirs(t, []string{"a", "b", "a/x"}, func(p string) bool { return p == "a" })

	// copy command /bin/true to /tmp so that we can effectively filter based on binary
	tmpTrue := testutils.CopyExecToTemp(t, "true")
	progTester := testprogs.StartTester(t, context.Background())

	type testCase struct {
		cgPath         string // cgroup path
		expCgID        uint64 // expected cgroup id
		expCgTrackerID uint64 // expetect cgroup tracker id
	}

	tcs := []testCase{
		{cgPath: "a", expCgID: cgfs.cgIDs["a"], expCgTrackerID: cgfs.cgIDs["a"]},
		{cgPath: "a/x", expCgID: cgfs.cgIDs["a/x"], expCgTrackerID: cgfs.cgIDs["a"]},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, tc := range tcs {
		// add tester to the specified cgroup
		progTester.AddToCgroup(t, cgfs.fullpath(tc.cgPath))

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

// test helper for creating cgroup directories
type testCgroupFS struct {
	dir          string
	cgTrackerMap cgtracker.Map
	paths        []string          // paths (in mkdir order, so that we can rmdir them in reverse order)
	cgIDs        map[string]uint64 // path -> cgid
}

func newTestCgroupFS(t *testing.T, cgfsPath string) *testCgroupFS {
	dir := cgfsMkdirTemp(t, cgfsPath)
	t.Logf("created cgroup dir '%s'", dir)

	mapFname := filepath.Join(bpf.MapPrefixPath(), cgtracker.MapName)
	m, err := cgtracker.OpenMap(mapFname)
	if err != nil {
		t.Fatalf("failed to open cgtracker map '%s': %s", mapFname, err)
	}

	ret := &testCgroupFS{
		dir:          dir,
		cgTrackerMap: m,
		cgIDs:        make(map[string]uint64),
	}

	t.Cleanup(func() { ret.cleanup(t) })
	return ret
}

func (fs *testCgroupFS) mkdirsCheck(
	t *testing.T,
	paths []string,
	trackPath func(p string) bool,
	checkFn func(t *testing.T, fs *testCgroupFS, p string),
) {
	for _, path := range paths {
		d := fs.fullpath(path)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatalf("failed to create '%s': %s", d, err)
		}
		if trackPath(path) {
			err := fs.cgTrackerMap.AddCgroupTrackerPath(d)
			require.NoError(t, err)
		}
		cgID, err := cgroups.GetCgroupIdFromPath(d)
		require.NoError(t, err)
		fs.cgIDs[path] = cgID
		t.Logf("cgid for %s is %d", path, cgID)
		if checkFn != nil {
			checkFn(t, fs, path)
		}
		fs.paths = append(fs.paths, path)
	}
}

func (fs *testCgroupFS) rmAllDirs(t *testing.T) {
	rmPaths := slices.Backward(fs.paths)
	// NB: not very efficient, but it allows us to test rmdirs
	fs.rmdirs(t, rmPaths)
}

func (fs *testCgroupFS) rmdirs(t *testing.T, paths iter.Seq2[int, string]) {
	for _, path := range paths {
		i := slices.Index(fs.paths, path)
		if i == -1 {
			t.Logf("path '%s' not part of testCgroupFS. calling rmdir anyway", path)
		}

		cgPath := fs.fullpath(path)
		if err := os.Remove(cgPath); err != nil {
			t.Fatalf("failed to unlink '%s': %s", cgPath, err)
		}

		delete(fs.cgIDs, path)
		if i != -1 {
			fs.paths = slices.Delete(fs.paths, i, i+1)
		}
	}
}

func (fs *testCgroupFS) mkdirs(
	t *testing.T,
	paths []string,
	trackPath func(p string) bool,
) {
	fs.mkdirsCheck(t, paths, trackPath, nil)
}

func (fs *testCgroupFS) fullpath(p string) string {
	return filepath.Join(fs.dir, p)
}

func (fs *testCgroupFS) cleanup(t *testing.T) {
	// remove the created directories
	for _, path := range slices.Backward(fs.paths) {
		cgPath := fs.fullpath(path)
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
	// close the bpf map
	fs.cgTrackerMap.Close()
}
