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

const testTarget = "/usr/lib64/libpam.so.0.85.1"

var errTestLoad = errors.New("test load failure")

// fakeSensors records the loaded sensors, by the binary each was built for.
type fakeSensors struct {
	mu        sync.Mutex
	loaded    map[string]string
	failBuild map[string]error
	failLoad  map[string]bool
	builds    int
	destroys  int
}

func newFakeSensors() *fakeSensors {
	return &fakeSensors{loaded: map[string]string{}, failBuild: map[string]error{}, failLoad: map[string]bool{}}
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
		if err := f.failBuild[target]; err != nil {
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

type fakeSensor struct {
	name, binary string
	owner        *fakeSensors
}

func (s *fakeSensor) Load(string) error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.owner.failLoad[s.binary] {
		return errTestLoad
	}
	s.owner.loaded[s.name] = s.binary
	return nil
}

func (s *fakeSensor) Destroy(bool) error {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	s.owner.destroys++
	delete(s.owner.loaded, s.name)
	return nil
}

// containerRoots gives each container its own root holding the target.
type containerRoots struct {
	base string
	skip []string
}

func newContainerRoots(t *testing.T, unresolvable ...string) *containerRoots {
	t.Helper()
	requireOpenat2InRoot(t)
	return &containerRoots{base: t.TempDir(), skip: unresolvable}
}

func (c *containerRoots) binary(containerID string) string {
	return filepath.Join(c.base, containerID, testTarget)
}

func (c *containerRoots) resolver() rootResolver {
	return func(_ context.Context, ch policyfilter.ContainerChange) (*containerRoot, error) {
		if slices.Contains(c.skip, ch.ContainerID) {
			return nil, errNotContainerProcess
		}
		binary := c.binary(ch.ContainerID)
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(binary, []byte("elf"), 0o755); err != nil {
			return nil, err
		}
		return &containerRoot{dir: filepath.Join(c.base, ch.ContainerID), mountPoint: "/", release: func() {}}, nil
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

func newTestReconciler(t *testing.T, sensors *fakeSensors, resolve rootResolver) *containerUprobeReconciler {
	t.Helper()
	r := newContainerUprobeReconciler("generic_uprobe_ric_0", testTarget, "", sensors.builder(), resolve)
	t.Cleanup(r.stop)
	return r
}

func TestReconcilerAttachDetach(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t)
	r := newTestReconciler(t, sensors, roots.resolver())

	r.apply(change("pod", "c1"))
	r.apply(change("pod", "c1"))
	require.Equal(t, []string{roots.binary("c1")}, sensors.binaries())
	require.Equal(t, 1, sensors.builds)

	r.apply(removal("pod", "other"))
	require.Len(t, sensors.binaries(), 1)

	r.apply(removal("pod", "c1"))
	require.Empty(t, sensors.binaries())
}

func TestReconcilerSkipsFailingContainers(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t, "unresolvable")
	r := newTestReconciler(t, sensors, roots.resolver())
	sensors.failBuild[roots.binary("other-build")] = &DigestMismatchError{Detail: "digest mismatch"}
	sensors.failLoad[roots.binary("broken")] = true

	for _, c := range []string{"unresolvable", "other-build", "broken", "ok"} {
		r.apply(change("pod", c))
	}

	require.Equal(t, []string{roots.binary("ok")}, sensors.binaries())
	require.Equal(t, 1, sensors.destroys)
}

func TestReconcilerBinaryCap(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t)
	r := newTestReconciler(t, sensors, roots.resolver())

	for i := range maxBinariesPerUprobe + 1 {
		r.apply(change("pod", "c"+strconv.Itoa(i)))
	}

	require.Len(t, sensors.binaries(), maxBinariesPerUprobe)
}

func TestReconcilerAppliesLatestChangeAndStops(t *testing.T) {
	sensors := newFakeSensors()
	roots := newContainerRoots(t)
	r := newTestReconciler(t, sensors, roots.resolver())

	r.push(change("pod", "c1"))
	r.push(removal("pod", "c1"))
	r.push(change("pod", "c2"))
	require.Eventually(t, func() bool {
		return slices.Equal([]string{roots.binary("c2")}, sensors.binaries())
	}, 5*time.Second, 10*time.Millisecond)

	r.stop()
	require.Empty(t, sensors.binaries())
}

func TestReconcilerStopAbortsLookup(t *testing.T) {
	sensors := newFakeSensors()
	resolving := make(chan struct{})
	var once sync.Once
	r := newTestReconciler(t, sensors, func(ctx context.Context, _ policyfilter.ContainerChange) (*containerRoot, error) {
		once.Do(func() { close(resolving) })
		<-ctx.Done()
		return nil, ctx.Err()
	})

	r.push(change("pod", "c1"))
	r.push(change("pod", "c2"))
	<-resolving
	r.stop()

	require.Zero(t, sensors.builds)
}
