// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errTestAttach = errors.New("test attach failure")

type fakeAttacher struct {
	mu       sync.Mutex
	attached map[string][]resolvedUprobe // key -> resolved uprobes
	failOn   map[string]error            // resolved attach path -> error to return from Attach
	detached []string                    // keys detached, in order
}

func newFakeAttacher() *fakeAttacher {
	return &fakeAttacher{
		attached: map[string][]resolvedUprobe{},
		failOn:   map[string]error{},
	}
}

func (f *fakeAttacher) Attach(key string, resolved []resolvedUprobe) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range resolved {
		if err := f.failOn[r.attachPath]; err != nil {
			return err
		}
	}
	f.attached[key] = resolved
	return nil
}

func (f *fakeAttacher) Detach(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.attached[key]; ok {
		delete(f.attached, key)
		f.detached = append(f.detached, key)
	}
}

func (f *fakeAttacher) attachedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.attached))
}

func (f *fakeAttacher) pathsOf(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.attached[key]
	paths := make([]string, 0, len(rs))
	for _, r := range rs {
		paths = append(paths, r.attachPath)
	}
	return paths
}

func (f *fakeAttacher) detachedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.detached)
}

func (f *fakeAttacher) attachmentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.attached)
}

func newTestReconciler(att Attacher) *containerUprobeReconciler {
	return newContainerUprobeReconciler(
		"/procRoot",
		[]string{"/usr/lib64/libpam.so.0.85.1"},
		att,
		fakeResolveRoot(),
	)
}

// fakeResolveRoot returns a rootResolver mapping a container id to
// /<procFS>/<containerID>/root, standing in for the runtime-hook / CRI resolver.
// Container ids listed in unresolvable (and the empty id) resolve to "", as if
// neither the runtime hook nor CRI knew the container.
func fakeResolveRoot(unresolvable ...string) rootResolver {
	skip := make(map[string]struct{}, len(unresolvable))
	for _, c := range unresolvable {
		skip[c] = struct{}{}
	}
	return func(containerID, procFS string) string {
		if _, no := skip[containerID]; no || containerID == "" {
			return ""
		}
		return procFS + "/" + containerID + "/root"
	}
}

func TestReconcilerAttachContainer(t *testing.T) {
	att := newFakeAttacher()
	r := newTestReconciler(att)

	r.onContainerAdd("podA/c1")

	require.Equal(t, []string{"podA/c1"}, att.attachedKeys())
	require.Equal(t, []string{"/procRoot/c1/root/usr/lib64/libpam.so.0.85.1"}, att.pathsOf("podA/c1"))
}

func TestReconcilerSoftFailPerContainer(t *testing.T) {
	att := newFakeAttacher()
	att.failOn["/procRoot/c2/root/usr/lib64/libpam.so.0.85.1"] = errTestAttach
	r := newTestReconciler(att)

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2") // fails
	r.onContainerAdd("podC/c3")

	require.Equal(t, []string{"podA/c1", "podC/c3"}, att.attachedKeys(),
		"a failing container must not block the others")
}

func TestReconcilerSkipUnresolvableRoot(t *testing.T) {
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot",
		[]string{"/usr/lib64/libpam.so.0.85.1"}, att, fakeResolveRoot("c1"))

	r.onContainerAdd("podA/c1")

	require.Empty(t, att.attachedKeys())
}

func TestReconcilerSnapshot(t *testing.T) {
	att := newFakeAttacher()
	r := newTestReconciler(att)

	// one container already attached before the snapshot.
	r.onContainerAdd("pod/c1")

	for _, key := range []string{
		"pod/c1", // already attached -> idempotent
		"pod/c2",
		"pod/c3",
	} {
		r.onContainerAdd(key)
	}

	require.Equal(t, []string{"pod/c1", "pod/c2", "pod/c3"}, att.attachedKeys())
	require.Equal(t, 3, r.attachedCount())
}

func TestReconcilerDetachAndIdempotentAdd(t *testing.T) {
	att := newFakeAttacher()
	r := newTestReconciler(att)

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podA/c1") // duplicate
	require.Equal(t, 1, r.attachedCount())

	r.onContainerDel("does-not-exist") // no-op
	require.Equal(t, 1, r.attachedCount())
	require.Empty(t, att.detachedKeys())

	r.onContainerDel("podA/c1")
	require.Equal(t, 0, r.attachedCount())
	require.Equal(t, []string{"podA/c1"}, att.detachedKeys())
	require.Empty(t, att.attachedKeys())
}

func TestReconcilerContainerCap(t *testing.T) {
	att := newFakeAttacher()
	r := newTestReconciler(att)
	r.maxContainers = 2

	r.onContainerAdd("pod/c1")
	r.onContainerAdd("pod/c2")
	r.onContainerAdd("pod/c3") // over the cap

	require.Equal(t, 2, r.attachedCount(), "attaches must stop at the cap")
	require.ElementsMatch(t, []string{"pod/c1", "pod/c2"}, att.attachedKeys())

	// freeing a slot lets a new container attach.
	r.onContainerDel("pod/c1")
	r.onContainerAdd("pod/c3")
	require.ElementsMatch(t, []string{"pod/c2", "pod/c3"}, att.attachedKeys())
}

func TestReconcilerMultipleTargets(t *testing.T) {
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []string{
		"/lib/a.so",
		"/lib/b.so",
	}, att, fakeResolveRoot())

	r.onContainerAdd("pod/c1")

	require.Equal(t, []string{"pod/c1#0", "pod/c1#1"}, att.attachedKeys())
	require.Equal(t, []string{"/procRoot/c1/root/lib/a.so"}, att.pathsOf("pod/c1#0"))
	require.Equal(t, []string{"/procRoot/c1/root/lib/b.so"}, att.pathsOf("pod/c1#1"))
}

func TestReconcilerMultipleTargetsAllOrNothing(t *testing.T) {
	att := newFakeAttacher()
	att.failOn["/procRoot/c1/root/lib/bad.so"] = errTestAttach
	r := newContainerUprobeReconciler("/procRoot", []string{
		"/lib/a.so",
		"/lib/bad.so",
	}, att, fakeResolveRoot())

	r.onContainerAdd("pod/c1")
	require.Empty(t, att.attachedKeys(), "a failing uprobe must skip the whole container")
}

func TestReconcilerSharesAttachmentForSameInode(t *testing.T) {
	rootA := filepath.Join(t.TempDir(), "root-a")
	rootB := filepath.Join(t.TempDir(), "root-b")
	pathA := filepath.Join(rootA, "usr", "bin", "app")
	pathB := filepath.Join(rootB, "usr", "bin", "app")
	require.NoError(t, os.MkdirAll(filepath.Dir(pathA), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(pathB), 0o755))
	require.NoError(t, os.WriteFile(pathA, []byte("shared executable"), 0o755))
	require.NoError(t, os.Link(pathA, pathB))

	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []string{"/usr/bin/app"}, att,
		func(containerID, _ string) string {
			switch containerID {
			case "c1":
				return rootA
			case "c2":
				return rootB
			default:
				return ""
			}
		})

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2")

	require.Equal(t, 2, r.attachedCount(), "both containers must be reference-counted")
	require.Equal(t, 1, att.attachmentCount(), "one policy probe must attach once to a shared inode")

	r.onContainerDel("podA/c1")
	require.Equal(t, 1, att.attachmentCount(), "the shared probe must outlive its first container reference")
	require.Empty(t, att.detachedKeys())

	r.onContainerDel("podB/c2")
	require.Zero(t, att.attachmentCount())
	require.Len(t, att.detachedKeys(), 1, "the shared probe must detach after its last reference")
}

func TestReconcilerDeduplicatesEachSpecIndependently(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	rootB := filepath.Join(base, "root-b")
	for _, root := range []string{rootA, rootB} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "lib"), 0o755))
	}
	sharedA := filepath.Join(rootA, "lib", "shared.so")
	sharedB := filepath.Join(rootB, "lib", "shared.so")
	require.NoError(t, os.WriteFile(sharedA, []byte("shared"), 0o755))
	require.NoError(t, os.Link(sharedA, sharedB))
	require.NoError(t, os.WriteFile(filepath.Join(rootA, "lib", "local.so"), []byte("a"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootB, "lib", "local.so"), []byte("b"), 0o755))

	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []string{
		"/lib/shared.so",
		"/lib/local.so",
	}, att, func(containerID, _ string) string {
		if containerID == "c1" {
			return rootA
		}
		return rootB
	})

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2")

	// spec 0 shares one inode; spec 1 resolves to distinct inodes.
	require.Equal(t, 3, att.attachmentCount(),
		"partial sharing must not duplicate the shared spec or drop either distinct spec")

	r.onContainerDel("podA/c1")
	require.Equal(t, 2, att.attachmentCount(), "shared spec and podB's distinct spec must remain")
	require.Len(t, att.detachedKeys(), 1)

	r.onContainerDel("podB/c2")
	require.Zero(t, att.attachmentCount())
	require.Len(t, att.detachedKeys(), 3)
}

type blockingDetachAttacher struct {
	*fakeAttacher
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *blockingDetachAttacher) Detach(key string) {
	f.once.Do(func() { close(f.started) })
	<-f.release
	f.fakeAttacher.Detach(key)
}

func TestReconcilerDetachAllWaitsForTeardown(t *testing.T) {
	att := &blockingDetachAttacher{
		fakeAttacher: newFakeAttacher(),
		started:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	r := newTestReconciler(att)
	r.onContainerAdd("pod/c1")

	done := make(chan struct{})
	go func() {
		r.detachAll()
		close(done)
	}()

	select {
	case <-att.started:
	case <-time.After(time.Second):
		t.Fatal("child teardown did not start")
	}
	select {
	case <-done:
		t.Fatal("detachAll returned before child teardown completed")
	default:
	}

	close(att.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("detachAll did not return after child teardown completed")
	}
	require.Zero(t, r.attachedCount())
}

func TestReconcilerConcurrentAddDelDetachAll(t *testing.T) {
	att := newRaceCheckAttacher()
	r := newTestReconciler(att)

	const workers = 16
	const keys = 8
	var wg sync.WaitGroup

	// concurrent adders and deleters over an overlapping key space.
	for w := range workers {
		wg.Go(func() {
			for i := range 200 {
				key := keyName(i % keys)
				if (w+i)%3 == 0 {
					r.onContainerDel(key)
				} else {
					r.onContainerAdd(key)
				}
			}
		})
	}
	// a concurrent snapshot-style sweep over all keys, racing the adders/deleters.
	wg.Go(func() {
		for range 50 {
			for i := range keys {
				r.onContainerAdd(keyName(i))
			}
		}
	})

	wg.Wait()

	require.Empty(t, att.failures(), "no double-attach or detach-of-unattached must occur")

	// After everything settles, detachAll must leave nothing attached, and a
	// subsequent add must be a no-op (closed).
	r.detachAll()
	require.Zero(t, r.attachedCount())
	require.Empty(t, att.attachedKeys())
	require.Empty(t, att.failures())

	r.onContainerAdd(keyName(0))
	require.Equal(t, 0, r.attachedCount(), "adds after detachAll must be no-ops")
	require.Empty(t, att.attachedKeys())
	require.Empty(t, att.failures())
}

func keyName(i int) string {
	return "pod/c" + strconv.Itoa(i)
}

// raceCheckAttacher is a fakeAttacher that fails loudly on a double-attach or a
// detach of a key that is not attached, so concurrency bugs surface as test
// failures rather than silent corruption.
type raceCheckAttacher struct {
	mu       sync.Mutex
	attached map[string]struct{}
	errs     []string
}

func newRaceCheckAttacher() *raceCheckAttacher {
	return &raceCheckAttacher{attached: map[string]struct{}{}}
}

func (f *raceCheckAttacher) Attach(key string, _ []resolvedUprobe) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.attached[key]; ok {
		f.errs = append(f.errs, "double attach: "+key)
	}
	f.attached[key] = struct{}{}
	return nil
}

func (f *raceCheckAttacher) Detach(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.attached[key]; !ok {
		f.errs = append(f.errs, "detach of unattached: "+key)
	}
	delete(f.attached, key)
}

func (f *raceCheckAttacher) attachedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.attached))
}

func (f *raceCheckAttacher) failures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.errs)
}
