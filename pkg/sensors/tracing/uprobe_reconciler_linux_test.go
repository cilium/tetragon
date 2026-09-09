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

	"github.com/stretchr/testify/require"
)

var errTestAttach = errors.New("test attach failure")

type fakeAttacher struct {
	mu       sync.Mutex
	attached map[string]string // key -> binary the pinned fd points at
	failOn   map[string]error  // that binary -> error from Attach
	detached []string          // keys detached, in order
	attempts int               // Attach calls, including failed ones
	errs     []string          // invariant violations seen
}

// requireOpenat2InRoot skips a test that needs the real containment resolver.
func requireOpenat2InRoot(t *testing.T) {
	t.Helper()
	if !hasOpenat2InRoot() {
		t.Skip("openat2(RESOLVE_IN_ROOT) not supported on this kernel")
	}
}

func newFakeAttacher() *fakeAttacher {
	return &fakeAttacher{
		attached: map[string]string{},
		failOn:   map[string]error{},
	}
}

// Attach resolves the pinned fd while it is still open, so tests can assert
// which binary the reconciler picked.
func (f *fakeAttacher) Attach(key, attachPath string) error {
	target, err := os.Readlink(attachPath)
	if err != nil {
		target = attachPath
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if err := f.failOn[target]; err != nil {
		return err
	}
	if _, ok := f.attached[key]; ok {
		f.errs = append(f.errs, "double attach: "+key)
	}
	f.attached[key] = target
	return nil
}

func (f *fakeAttacher) Detach(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.attached[key]; !ok {
		f.errs = append(f.errs, "detach of unattached: "+key)
		return
	}
	delete(f.attached, key)
	f.detached = append(f.detached, key)
}

// failures reports attach/detach sequences no reconciler should produce.
func (f *fakeAttacher) failures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.errs)
}

func (f *fakeAttacher) attachCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

func (f *fakeAttacher) attachedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.attached))
}

// pathOf returns the binary the uprobe attached for key points at.
func (f *fakeAttacher) pathOf(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attached[key]
}

func (f *fakeAttacher) detachedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.detached)
}

func (r *containerUprobeReconciler) attachedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attached)
}

const testTarget = "/usr/lib64/libpam.so.0.85.1"

// containerRoots gives each container id a real root directory holding the
// policy target, so the reconciler runs the real openat2 resolver. Ids listed
// as unresolvable get no root, as if no container process was found.
type containerRoots struct {
	base   string
	target string
	skip   map[string]struct{}
	mu     sync.Mutex
}

func newContainerRoots(t *testing.T, target string, unresolvable ...string) *containerRoots {
	t.Helper()
	requireOpenat2InRoot(t)
	skip := make(map[string]struct{}, len(unresolvable))
	for _, c := range unresolvable {
		skip[c] = struct{}{}
	}
	return &containerRoots{base: t.TempDir(), target: target, skip: skip}
}

// binary is the host path of the target inside containerID's root.
func (c *containerRoots) binary(containerID string) string {
	return filepath.Join(c.base, containerID, c.target)
}

func (c *containerRoots) resolver() rootResolver {
	return func(containerID string) string {
		if _, no := c.skip[containerID]; no || containerID == "" {
			return ""
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		binary := c.binary(containerID)
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return ""
		}
		if err := os.WriteFile(binary, []byte("elf"), 0o755); err != nil {
			return ""
		}
		return filepath.Join(c.base, containerID)
	}
}

func newTestReconciler(t *testing.T, att attacher) (*containerUprobeReconciler, *containerRoots) {
	t.Helper()
	roots := newContainerRoots(t, testTarget)
	return newContainerUprobeReconciler("", testTarget, att, roots.resolver()), roots
}

func TestReconcilerAttachContainer(t *testing.T) {
	att := newFakeAttacher()
	r, roots := newTestReconciler(t, att)

	r.onContainerAdd("podA/c1")

	require.Equal(t, []string{"podA/c1"}, att.attachedKeys())
	require.Equal(t, roots.binary("c1"), att.pathOf("podA/c1"),
		"the uprobe must attach to the binary inside that container")
}

func TestReconcilerSoftFailPerContainer(t *testing.T) {
	att := newFakeAttacher()
	r, roots := newTestReconciler(t, att)
	att.failOn[roots.binary("c2")] = errTestAttach

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2") // fails
	r.onContainerAdd("podC/c3")

	require.Equal(t, []string{"podA/c1", "podC/c3"}, att.attachedKeys(),
		"a failing container must not block the others")
}

// A container whose binary does not match binaryDigests is skipped like one
// missing the path, without failing the policy.
func TestReconcilerSkipsDigestMismatch(t *testing.T) {
	att := newFakeAttacher()
	r, roots := newTestReconciler(t, att)
	att.failOn[roots.binary("c1")] = &DigestMismatchError{Detail: "digest mismatch"}

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podB/c2")

	require.Equal(t, []string{"podB/c2"}, att.attachedKeys())
}

func TestReconcilerSkipUnresolvableRoot(t *testing.T) {
	att := newFakeAttacher()
	roots := newContainerRoots(t, testTarget, "c1")
	r := newContainerUprobeReconciler("", testTarget, att, roots.resolver())

	r.onContainerAdd("podA/c1")

	require.Empty(t, att.attachedKeys())
}

// A container that does not ship the policy's binary is skipped without
// failing the policy for the others.
func TestReconcilerSkipMissingTarget(t *testing.T) {
	att := newFakeAttacher()
	roots := newContainerRoots(t, testTarget)
	r := newContainerUprobeReconciler("", "/usr/bin/absent", att, roots.resolver())

	r.onContainerAdd("podA/c1")

	require.Empty(t, att.attachedKeys())
}

func TestReconcilerDetachAndIdempotentAdd(t *testing.T) {
	att := newFakeAttacher()
	r, _ := newTestReconciler(t, att)

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podA/c1") // duplicate
	require.Equal(t, 1, r.attachedCount())
	require.Equal(t, 1, att.attachCount(), "a repeated add must not re-attach")

	r.onContainerDel("does-not-exist") // no-op
	require.Equal(t, 1, r.attachedCount())
	require.Empty(t, att.detachedKeys())

	r.onContainerDel("podA/c1")
	require.Equal(t, 0, r.attachedCount())
	require.Equal(t, []string{"podA/c1"}, att.detachedKeys())
	require.Empty(t, att.attachedKeys())
}

// A pod delete carries terminated statuses, so the reconciler detaches every
// container of the pod by key prefix.
func TestReconcilerPodDelete(t *testing.T) {
	att := newFakeAttacher()
	r, _ := newTestReconciler(t, att)

	r.onContainerAdd("podA/c1")
	r.onContainerAdd("podA/c2")
	r.onContainerAdd("podB/c3")

	r.onPodDel("podA")

	require.Equal(t, []string{"podB/c3"}, att.attachedKeys())
}

func TestReconcilerContainerCap(t *testing.T) {
	att := newFakeAttacher()
	r, _ := newTestReconciler(t, att)
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

// Containers whose binary is the same inode share one uprobe, which outlives
// its first container reference.
func TestReconcilerSharesAttachmentByInodeWithoutOverlay(t *testing.T) {
	rootA := filepath.Join(t.TempDir(), "root-a")
	rootB := filepath.Join(t.TempDir(), "root-b")
	pathA := filepath.Join(rootA, "usr", "bin", "app")
	pathB := filepath.Join(rootB, "usr", "bin", "app")
	require.NoError(t, os.MkdirAll(filepath.Dir(pathA), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(pathB), 0o755))
	require.NoError(t, os.WriteFile(pathA, []byte("shared executable"), 0o755))
	require.NoError(t, os.Link(pathA, pathB))

	att := newFakeAttacher()
	requireOpenat2InRoot(t)
	r := newContainerUprobeReconciler("", "/usr/bin/app", att, func(containerID string) string {
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
	require.Len(t, att.attachedKeys(), 1, "one uprobe must attach once to a shared inode")

	r.onContainerDel("podA/c1")
	require.Len(t, att.attachedKeys(), 1, "the shared uprobe must outlive its first reference")
	require.Empty(t, att.detachedKeys())

	r.onContainerDel("podB/c2")
	require.Empty(t, att.attachedKeys())
	require.Len(t, att.detachedKeys(), 1, "the shared uprobe must detach after its last reference")
}

// markWanted claims containers running at policy load; a delete arriving
// before the attach wins, since both take the same lock.
func TestReconcilerMarkWantedThenAttach(t *testing.T) {
	att := newFakeAttacher()
	r, _ := newTestReconciler(t, att)

	r.markWanted("pod/c1", "pod/c2")
	r.onContainerDel("pod/c2")
	for _, k := range []string{"pod/c1", "pod/c2"} {
		r.attachWanted(k)
	}

	require.Equal(t, []string{"pod/c1"}, att.attachedKeys(),
		"a container deleted before its initial attach must not be attached")
}

func TestReconcilerConcurrentAddDelDetachAll(t *testing.T) {
	att := newFakeAttacher()
	r, _ := newTestReconciler(t, att)

	const workers = 8
	const keys = 4
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range 100 {
				key := "pod/c" + strconv.Itoa(i%keys)
				if (w+i)%3 == 0 {
					r.onContainerDel(key)
				} else {
					r.onContainerAdd(key)
				}
			}
		})
	}
	wg.Wait()

	require.Empty(t, att.failures(), "no double-attach or detach-of-unattached must occur")

	// detachAll must leave nothing attached, and a later add must be a no-op.
	r.detachAll()
	require.Zero(t, r.attachedCount())
	require.Empty(t, att.attachedKeys())

	r.onContainerAdd("pod/c0")
	require.Zero(t, r.attachedCount(), "adds after detachAll must be no-ops")
	require.Empty(t, att.failures())
}

func TestContainerIDFromKey(t *testing.T) {
	require.Equal(t, "c1", containerIDFromKey("podA/c1"))
	require.Equal(t, "c", containerIDFromKey("a/b/c"))
	require.Equal(t, "noseparator", containerIDFromKey("noseparator"))
}
