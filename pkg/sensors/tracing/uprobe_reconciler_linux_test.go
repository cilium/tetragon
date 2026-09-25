// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/policyfilter"
)

var errTestLoad = errors.New("test load failure")

// fakeSensors records the child sensors a reconciler builds, by the binary
// each was built for.
type fakeSensors struct {
	mu      sync.Mutex
	loaded  map[string]string // sensor name -> binary
	failOn  map[string]error  // binary -> build error
	builds  int
	destroy int
}

func newFakeSensors() *fakeSensors {
	return &fakeSensors{loaded: map[string]string{}, failOn: map[string]error{}}
}

func (f *fakeSensors) builder() sensorBuilder {
	return func(name string, binary *os.File) (loadedSensor, error) {
		target, err := os.Readlink(procSelfFDPath(int(binary.Fd())))
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.builds++
		if err := f.failOn[target]; err != nil {
			return nil, err
		}
		return &fakeSensor{name: name, binary: target, owner: f}, nil
	}
}

func (f *fakeSensors) binaries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Values(f.loaded))
}

func (f *fakeSensors) buildCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.builds
}

type fakeSensor struct {
	name, binary string
	owner        *fakeSensors
	loadErr      error
}

func (s *fakeSensor) Load(string) error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	s.owner.loaded[s.name] = s.binary
	return nil
}

func (s *fakeSensor) Destroy(bool) error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.owner.destroy++
	delete(s.owner.loaded, s.name)
	return nil
}

// containerRoots creates a root holding the target for each container it is
// asked to resolve, unless the container is listed as unresolvable.
type containerRoots struct {
	base   string
	target string
	skip   map[string]struct{}
}

func newContainerRoots(t *testing.T, target string, unresolvable ...string) *containerRoots {
	t.Helper()
	requireOpenat2InRoot(t)
	skip := map[string]struct{}{}
	for _, c := range unresolvable {
		skip[c] = struct{}{}
	}
	return &containerRoots{base: t.TempDir(), target: target, skip: skip}
}

func (c *containerRoots) binary(containerID string) string {
	return filepath.Join(c.base, containerID, c.target)
}

func (c *containerRoots) resolver() rootResolver {
	return func(_ context.Context, ch policyfilter.ContainerChange) (*containerRoot, error) {
		if _, no := c.skip[ch.ContainerID]; no {
			return nil, errNotContainerProcess
		}
		binary := c.binary(ch.ContainerID)
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(binary, []byte("elf"), 0o755); err != nil {
			return nil, err
		}
		return testRoot(filepath.Join(c.base, ch.ContainerID)), nil
	}
}

func testRoot(dir string) *containerRoot {
	return &containerRoot{dir: dir, mountPoint: "/", release: func() {}}
}

func dirResolver(dirs map[string]string) rootResolver {
	return func(_ context.Context, ch policyfilter.ContainerChange) (*containerRoot, error) {
		return testRoot(dirs[ch.ContainerID]), nil
	}
}

var testPods = map[string]policyfilter.PodID{}

func change(pod, containerID string) policyfilter.ContainerChange {
	id, ok := testPods[pod]
	if !ok {
		id = policyfilter.PodID(uuid.New())
		testPods[pod] = id
	}
	return policyfilter.ContainerChange{PodID: id, ContainerID: containerID}
}

func removal(pod, containerID string) policyfilter.ContainerChange {
	c := change(pod, containerID)
	c.Removed = true
	return c
}

const testTarget = "/usr/lib64/libpam.so.0.85.1"

func newTestReconciler(t *testing.T, target string, sensors *fakeSensors, resolve rootResolver) *containerUprobeReconciler {
	t.Helper()
	r := newContainerUprobeReconciler("", target, "", sensors.builder(), resolve)
	t.Cleanup(r.stop)
	return r
}

func (r *containerUprobeReconciler) containers() []string {
	var out []string
	for ref := range r.attached {
		out = append(out, ref.containerID)
	}
	slices.Sort(out)
	return out
}

func TestReconcilerAttachContainer(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	r := newTestReconciler(t, testTarget, sensors, roots.resolver())

	r.apply(change("podA", "c1"))

	require.Equal(t, []string{"c1"}, r.containers())
	require.Equal(t, []string{roots.binary("c1")}, sensors.binaries())
}

func TestReconcilerSkipsFailingContainers(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget, "unresolvable")
	r := newTestReconciler(t, testTarget, sensors, roots.resolver())
	sensors.failOn[roots.binary("broken")] = errTestLoad
	sensors.failOn[roots.binary("other-build")] = &DigestMismatchError{Detail: "digest mismatch"}

	for _, c := range []string{"unresolvable", "broken", "other-build", "ok"} {
		r.apply(change("pod", c))
	}

	require.Equal(t, []string{"ok"}, r.containers())
}

func TestReconcilerSkipsMissingTarget(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	r := newTestReconciler(t, "/usr/bin/absent", sensors, roots.resolver())

	r.apply(change("podA", "c1"))

	require.Empty(t, r.containers())
	require.Zero(t, sensors.builds)
}

func TestReconcilerDestroysSensorOnLoadFailure(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	build := sensors.builder()
	r := newContainerUprobeReconciler("", testTarget, "", func(name string, binary *os.File) (loadedSensor, error) {
		s, err := build(name, binary)
		s.(*fakeSensor).loadErr = errTestLoad
		return s, err
	}, roots.resolver())
	t.Cleanup(r.stop)

	r.apply(change("podA", "c1"))

	require.Empty(t, r.containers())
	require.Equal(t, 1, sensors.destroy)
}

func TestReconcilerDetachAndIdempotentAdd(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	r := newTestReconciler(t, testTarget, sensors, roots.resolver())

	r.apply(change("podA", "c1"))
	r.apply(change("podA", "c1"))
	require.Equal(t, 1, sensors.builds)

	r.apply(removal("podA", "none"))
	require.Equal(t, []string{"c1"}, r.containers())

	r.apply(removal("podA", "c1"))
	require.Empty(t, r.containers())
	require.Empty(t, sensors.binaries())
}

func TestReconcilerBinaryCap(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	r := newTestReconciler(t, testTarget, sensors, roots.resolver())

	for i := range maxBinariesPerPolicy + 1 {
		r.apply(change("pod", "c"+strconv.Itoa(i)))
	}
	require.Len(t, sensors.binaries(), maxBinariesPerPolicy)

	r.apply(removal("pod", "c0"))
	r.apply(change("pod", "c"+strconv.Itoa(maxBinariesPerPolicy)))
	require.Len(t, sensors.binaries(), maxBinariesPerPolicy)
	require.Contains(t, sensors.binaries(), roots.binary("c"+strconv.Itoa(maxBinariesPerPolicy)))
}

func TestReconcilerSharesSensorByInodeWithoutOverlay(t *testing.T) {
	requireOpenat2InRoot(t)
	rootA := filepath.Join(t.TempDir(), "root-a")
	rootB := filepath.Join(t.TempDir(), "root-b")
	pathA := filepath.Join(rootA, "usr", "bin", "app")
	pathB := filepath.Join(rootB, "usr", "bin", "app")
	require.NoError(t, os.MkdirAll(filepath.Dir(pathA), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(pathB), 0o755))
	require.NoError(t, os.WriteFile(pathA, []byte("shared executable"), 0o755))
	require.NoError(t, os.Link(pathA, pathB))

	sensors := newFakeSensors()
	r := newTestReconciler(t, "/usr/bin/app", sensors, dirResolver(map[string]string{"c1": rootA, "c2": rootB}))

	r.apply(change("podA", "c1"))
	r.apply(change("podB", "c2"))
	require.Equal(t, []string{"c1", "c2"}, r.containers())
	require.Len(t, sensors.binaries(), 1)

	r.apply(removal("podA", "c1"))
	require.Len(t, sensors.binaries(), 1)
	r.apply(removal("podB", "c2"))
	require.Empty(t, sensors.binaries())
}

func TestReconcilerAppliesLatestChangeAndStops(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, testTarget)
	r := newContainerUprobeReconciler("", testTarget, "", sensors.builder(), roots.resolver())

	// A removal queued behind its add must win.
	r.push(change("pod", "c1"))
	r.push(removal("pod", "c1"))
	r.push(change("pod", "c2"))
	require.Eventually(t, func() bool {
		return slices.Equal([]string{roots.binary("c2")}, sensors.binaries())
	}, 5*time.Second, 10*time.Millisecond)

	r.stop()
	require.Empty(t, sensors.binaries())

	r.push(change("pod", "c3"))
	require.Empty(t, sensors.binaries())
}

func TestReconcilerStopSkipsQueuedChanges(t *testing.T) {
	sensors := newFakeSensors()
	resolving := make(chan struct{})
	var once sync.Once
	r := newContainerUprobeReconciler("", testTarget, "", sensors.builder(),
		func(ctx context.Context, _ policyfilter.ContainerChange) (*containerRoot, error) {
			// The first lookup blocks until the stop cancels it.
			once.Do(func() { close(resolving) })
			<-ctx.Done()
			return nil, ctx.Err()
		})

	for i := range 10 {
		r.push(change("pod", "c"+strconv.Itoa(i)))
	}
	<-resolving
	r.stop()

	require.Zero(t, sensors.buildCount())
}
