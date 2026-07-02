// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errTestAttach = errors.New("test attach failure")

// fakeAttacher records attach/detach calls instead of touching BPF, so the
// reconciler logic can be exercised without a kernel. It is mutex-guarded so it
// is safe to use from the concurrency (-race) test.
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
	keys := make([]string, 0, len(f.attached))
	for k := range f.attached {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *fakeAttacher) pathOf(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.attached[key]
	if len(rs) == 0 {
		return ""
	}
	return rs[0].attachPath
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
	return append([]string(nil), f.detached...)
}

func newTestReconciler(att Attacher) *containerUprobeReconciler {
	return newContainerUprobeReconciler(
		"/procRoot",
		[]ricTarget{{path: "/usr/lib64/libpam.so.0.85.1"}},
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

// T4: a matching container is resolved under its container root and attached.
func TestReconcilerAttachContainer(t *testing.T) {
	att := newFakeAttacher()
	r := newTestReconciler(att)

	r.onContainerAdd("podA/c1")

	require.Equal(t, []string{"podA/c1"}, att.attachedKeys())
	require.Equal(t, "/procRoot/c1/root/usr/lib64/libpam.so.0.85.1", att.pathOf("podA/c1"))
}

// T4: per-container soft-fail — a container whose path cannot be resolved/attached
// must not prevent other containers from attaching.
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

// T4: a container whose root cannot be resolved (no runtime-hook/CRI info) is
// skipped, not attached.
func TestReconcilerSkipUnresolvableRoot(t *testing.T) {
	att := newFakeAttacher()
	// c1 resolves to no rthook/CRI root.
	r := newContainerUprobeReconciler("/procRoot",
		[]ricTarget{{path: "/usr/lib64/libpam.so.0.85.1"}}, att, fakeResolveRoot("c1"))

	r.onContainerAdd("podA/c1")

	require.Empty(t, att.attachedKeys())
}

// T6: re-driving a batch of currently-matching containers (the snapshot/resync
// path: policy applied after pods already exist, agent restart) attaches them
// all, idempotently with respect to already-attached containers.
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

// T4: detaching a container removes its attach; detaching an unknown key is a
// no-op; adding the same container twice attaches only once (idempotent).
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

// H: the per-policy container cap bounds how many containers attach; beyond the
// cap, containers are skipped rather than loading unbounded BPF programs.
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

// N RIC uprobes: a reconciler with multiple targets resolves all of them and
// attaches them together for one container (index-aligned).
func TestReconcilerMultipleTargets(t *testing.T) {
	att := newFakeAttacher()
	r := newContainerUprobeReconciler("/procRoot", []ricTarget{
		{path: "/lib/a.so"},
		{path: "/lib/b.so"},
	}, att, fakeResolveRoot())

	r.onContainerAdd("pod/c1")

	require.Equal(t, []string{"pod/c1"}, att.attachedKeys())
	require.Equal(t, []string{
		"/procRoot/c1/root/lib/a.so",
		"/procRoot/c1/root/lib/b.so",
	}, att.pathsOf("pod/c1"))
}

// All-or-nothing: if one of the N uprobes fails to attach, the whole container
// is skipped (no partial attach).
func TestReconcilerMultipleTargetsAllOrNothing(t *testing.T) {
	att := newFakeAttacher()
	att.failOn["/procRoot/c1/root/lib/bad.so"] = errTestAttach
	r := newContainerUprobeReconciler("/procRoot", []ricTarget{
		{path: "/lib/a.so"},
		{path: "/lib/bad.so"},
	}, att, fakeResolveRoot())

	r.onContainerAdd("pod/c1")
	require.Empty(t, att.attachedKeys(), "a failing uprobe must skip the whole container")
}

// C1/C2/C3: drive the reconciler concurrently from many goroutines — adds,
// deletes, snapshots, and a detachAll — and assert no double-attach, no leak,
// and (under -race) no data race. The fake attacher panics on a double-attach
// or a detach of something not attached, so a TOCTOU bug fails the test.
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
	// subsequent add must be a no-op (closed). detachAll detaches on its own
	// goroutine, so wait for it to drain.
	r.detachAll()
	require.Eventually(t, func() bool {
		return r.attachedCount() == 0 && len(att.attachedKeys()) == 0
	}, time.Second, time.Millisecond, "detachAll must asynchronously detach everything")
	require.Empty(t, att.failures())

	r.onContainerAdd(keyName(0))
	require.Equal(t, 0, r.attachedCount(), "adds after detachAll must be no-ops")
	require.Empty(t, att.attachedKeys())
	require.Empty(t, att.failures())
}

func keyName(i int) string {
	return "pod/c" + string(rune('0'+i))
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
	keys := make([]string, 0, len(f.attached))
	for k := range f.attached {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *raceCheckAttacher) failures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.errs...)
}
