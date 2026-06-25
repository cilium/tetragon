// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// rootResolver resolves a container id to an openable root directory,
// returning "" when unresolved so the caller retries. Injected to keep the
// reconciler free of build-tagged CRI/rthook code.
type rootResolver func(containerID string, procFS string) string

// defaultMaxContainersPerPolicy caps attached containers per policy: each
// attach loads its own BPF program and maps.
const defaultMaxContainersPerPolicy = 1000

// resolvedUprobe is an in-container target path resolved inside a container;
// index-aligned with the policy's RIC uprobes.
type resolvedUprobe struct {
	targetIndex int    // index in the policy's RIC uprobes
	attachPath  string // resolved binary path (e.g. /proc/self/fd/N)
	fileID      string // stable device/inode identity while attachPath is open
}

// Attacher attaches and detaches the per-container uprobe sensor for a key.
// The real implementation loads/unloads a per-container sensor; tests fake it.
type Attacher interface {
	// Attach attaches one policy uprobe spec to one resolved inode for key;
	// must be idempotent for a repeated key.
	Attach(key string, resolved []resolvedUprobe) error
	// Detach removes the uprobes attached for key; no-op if never attached.
	Detach(key string)
}

// containerUprobeReconciler drives uprobe attach/detach per policy as
// containers come and go; created fresh on each policy load. It holds no BPF
// state, delegating to an Attacher so it is unit-testable without a kernel.
type containerUprobeReconciler struct {
	procFS string
	// targets are the in-container binary paths, index-aligned with the RIC
	// uprobes.
	targets       []string
	att           Attacher
	resolveRoot   rootResolver
	maxContainers int

	// versionMu is a short-lived ordering lock, never held during root
	// resolution or sensor-manager calls, so pod handlers can invalidate every
	// affected policy before starting slow work.
	versionMu sync.Mutex
	version   uint64 // advances on live mutations and snapshot starts

	// mu serializes the whole attach/detach for a container: concurrent
	// add/del for the same key must not double-attach or race.
	mu       sync.Mutex
	attached map[string][]string        // container key -> policy-spec/inode identities
	probes   map[string]*attachedUprobe // policy-spec/inode identity -> shared attachment
	wanted   map[string]struct{}        // keys actively desired (add received, no delete yet)
	// closed is set by detachAll; further adds are no-ops so a late snapshot
	// cannot attach and leak a container.
	closed bool
	// capWarnOnce warns once when the cap truncates coverage; the resync would
	// otherwise repeat it forever.
	capWarnOnce sync.Once
}

type attachedUprobe struct {
	key  string // key used by the Attacher
	refs int    // containers using this policy-spec/inode pair
}

type reconcileSnapshotToken uint64

func newContainerUprobeReconciler(procFS string, targets []string, att Attacher, resolveRoot rootResolver) *containerUprobeReconciler {
	return &containerUprobeReconciler{
		procFS:        procFS,
		targets:       targets,
		att:           att,
		resolveRoot:   resolveRoot,
		maxContainers: defaultMaxContainersPerPolicy,
		attached:      map[string][]string{},
		probes:        map[string]*attachedUprobe{},
		wanted:        map[string]struct{}{},
	}
}

// admitLocked reports whether key can attach: not closed, not already
// attached, and under the per-policy cap. Caller must hold r.mu.
func (r *containerUprobeReconciler) admitLocked(key string) bool {
	if r.closed {
		return false
	}
	if _, already := r.attached[key]; already {
		return false
	}
	if len(r.attached) >= r.maxContainers {
		// Warn once so silently-incomplete coverage is discoverable; Debug the
		// rest, since the resync would otherwise repeat the Warn every interval.
		r.capWarnOnce.Do(func() {
			logger.GetLogger().Warn("uprobe resolvePathInContainer: per-policy container cap reached; "+
				"further matching containers will not be traced until others detach",
				"cap", r.maxContainers)
		})
		logger.GetLogger().Debug("uprobe reconciler: per-policy container cap reached, skipping container",
			"key", key, "cap", r.maxContainers)
		return false
	}
	return true
}

// admitWanted reports whether resolution should proceed; the attach re-checks
// under the lock after the off-lock resolution. markWanted is true for
// informer adds; exact reconciliations mark their desired set first and pass
// false so a newer prune cannot be undone by stale off-lock work.
func (r *containerUprobeReconciler) admitWanted(key string, markWanted bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if markWanted {
		if r.closed {
			return false
		}
		r.advanceVersion()
		r.wanted[key] = struct{}{}
	}
	if !r.admitLocked(key) {
		return false
	}
	if !markWanted {
		if _, wanted := r.wanted[key]; !wanted {
			return false
		}
	}
	return true
}

// beginSnapshot reserves a version before slow snapshot collection. A later
// pod event or snapshot start invalidates the returned token.
func (r *containerUprobeReconciler) beginSnapshot() reconcileSnapshotToken {
	r.versionMu.Lock()
	defer r.versionMu.Unlock()
	r.version++
	return reconcileSnapshotToken(r.version)
}

// invalidateSnapshots marks a live informer event before its handler performs
// any potentially slow per-container work.
func (r *containerUprobeReconciler) invalidateSnapshots() {
	r.advanceVersion()
}

func (r *containerUprobeReconciler) advanceVersion() {
	r.versionMu.Lock()
	r.version++
	r.versionMu.Unlock()
}

// containerRoot returns an openable root directory for the keyed container via
// the injected resolver, or "" when it cannot be resolved yet.
func (r *containerUprobeReconciler) containerRoot(key string) string {
	if r.resolveRoot == nil {
		return ""
	}
	return r.resolveRoot(containerIDFromKey(key), r.procFS)
}

// containerIDFromKey extracts the container id from a "<podID>/<containerID>" key.
func containerIDFromKey(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// resolvedFileID returns a stable identity for a resolved attach path: a
// device/inode pair for fd-backed paths, the path itself for test fakes whose
// roots do not exist (a real attach at such a path fails in the builder).
func resolvedFileID(attachPath string) string {
	var st unix.Stat_t
	if err := unix.Stat(attachPath, &st); err == nil {
		return fmt.Sprintf("inode:%d:%d", uint64(st.Dev), st.Ino)
	}
	return "path:" + attachPath
}

func resolvedAttachmentID(targetIndex int, fileID string) string {
	return fmt.Sprintf("%d:%d:%s", targetIndex, len(fileID), fileID)
}

// onContainerAdd resolves every RIC uprobe path inside the keyed container
// and attaches them all-or-nothing; any failure skips the whole container to
// be retried later.
func (r *containerUprobeReconciler) onContainerAdd(key string) {
	r.onContainerAddWanted(key, true)
}

func (r *containerUprobeReconciler) onContainerAddWanted(key string, markWanted bool) {
	if !r.admitWanted(key, markWanted) {
		return
	}
	resolved, cleanup, ok := r.resolveContainerTargets(key)
	if !ok {
		return
	}
	defer cleanup()

	// Hold the lock across the attach so a concurrent add cannot double-attach
	// and a concurrent detach cannot race it.
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attachResolvedLocked(key, resolved)
}

// resolveContainerTargets resolves every RIC target inside the keyed container,
// holding each fd open via the returned cleanup, which the caller must invoke
// after the attach completes. ok is false (and any fds already opened are
// closed) when the root or any target cannot be resolved.
func (r *containerUprobeReconciler) resolveContainerTargets(key string) ([]resolvedUprobe, func(), bool) {
	root := r.containerRoot(key)
	if root == "" {
		// Neither the runtime hook nor CRI resolved a root yet; retried on a
		// later pod update or resync.
		logger.GetLogger().Debug("uprobe reconciler: skipping container with no resolvable root",
			"key", key)
		return nil, func() {}, false
	}

	var closers []func()
	cleanup := func() {
		for _, f := range closers {
			f()
		}
	}
	resolved := make([]resolvedUprobe, len(r.targets))
	for i, t := range r.targets {
		rp, closeFn, err := resolveBinaryUnderRoot(root, t)
		if err != nil {
			// ENOENT is expected for sidecar containers lacking the target
			// binary; Debug so the resync does not spam Warn.
			if errors.Is(err, unix.ENOENT) {
				logger.GetLogger().Debug("uprobe reconciler: path not present in container, skipping container",
					logfields.Error, err, "key", key, "root", root, "path", t)
			} else {
				logger.GetLogger().Warn("uprobe reconciler: failed to resolve container path, skipping container",
					logfields.Error, err, "key", key, "root", root, "path", t)
			}
			cleanup()
			return nil, func() {}, false
		}
		closers = append(closers, closeFn)
		resolved[i] = resolvedUprobe{
			targetIndex: i,
			attachPath:  rp,
			fileID:      resolvedFileID(rp),
		}
	}
	return resolved, cleanup, true
}

// attachResolvedLocked attaches the resolved set all-or-nothing; the caller
// must hold r.mu. Each policy spec attaches independently: a shared spec/inode
// pair has one uprobe and a container refcount, and earlier specs roll back if
// a later one fails.
func (r *containerUprobeReconciler) attachResolvedLocked(key string, resolved []resolvedUprobe) {
	if !r.admitLocked(key) {
		return
	}
	if _, active := r.wanted[key]; !active {
		logger.GetLogger().Debug("uprobe reconciler: skipping container attach, no longer wanted",
			"key", key)
		return
	}

	identities := make([]string, 0, len(resolved))
	for i := range resolved {
		identity := resolvedAttachmentID(resolved[i].targetIndex, resolved[i].fileID)
		probe := r.probes[identity]
		if probe == nil {
			attachKey := key
			if len(resolved) > 1 {
				attachKey = fmt.Sprintf("%s#%d", key, resolved[i].targetIndex)
			}
			if err := r.att.Attach(attachKey, resolved[i:i+1]); err != nil {
				r.releaseProbesLocked(identities)
				// A digest mismatch is an expected skip (a container running a
				// different build), like a missing path; Debug so the resync
				// does not spam Warn.
				var mismatch *DigestMismatchError
				if errors.As(err, &mismatch) {
					logger.GetLogger().Debug("uprobe reconciler: container binary digest mismatch, skipping container",
						logfields.Error, err, "key", key)
				} else {
					logger.GetLogger().Warn("uprobe reconciler: failed to attach uprobe in container, skipping container",
						logfields.Error, err, "key", key)
				}
				return
			}
			probe = &attachedUprobe{key: attachKey}
			r.probes[identity] = probe
		}
		probe.refs++
		identities = append(identities, identity)
	}
	r.attached[key] = identities
}

func (r *containerUprobeReconciler) releaseProbesLocked(identities []string) {
	for _, identity := range identities {
		probe := r.probes[identity]
		if probe == nil {
			continue
		}
		probe.refs--
		if probe.refs == 0 {
			r.att.Detach(probe.key)
			delete(r.probes, identity)
		}
	}
}

func (r *containerUprobeReconciler) detachContainerLocked(key string) {
	identities, ok := r.attached[key]
	if !ok {
		return
	}
	delete(r.attached, key)
	r.releaseProbesLocked(identities)
}

// onContainerDel detaches the keyed container under the lock so it cannot
// interleave with an attach; it runs off the manager collection lock.
func (r *containerUprobeReconciler) onContainerDel(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.advanceVersion()
	delete(r.wanted, key)
	r.detachContainerLocked(key)
}

// onPodDel detaches the pod's containers by "<podUID>/" key prefix: delete
// events usually carry only terminated statuses, so they cannot enumerate
// what was attached.
func (r *containerUprobeReconciler) onPodDel(podUID string) {
	prefix := podUID + "/"
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.advanceVersion()
	for k := range r.wanted {
		if strings.HasPrefix(k, prefix) {
			delete(r.wanted, k)
		}
	}
	for k := range r.attached {
		if strings.HasPrefix(k, prefix) {
			r.detachContainerLocked(k)
		}
	}
}

// reconcileContainers applies an exact desired set only if token is still the
// latest pod/snapshot version. The version check and wanted-state replacement
// are atomic; slow resolution and sensor-manager calls run off that lock.
func (r *containerUprobeReconciler) reconcileContainers(token reconcileSnapshotToken, desired map[string]struct{}) bool {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	r.versionMu.Lock()
	if reconcileSnapshotToken(r.version) != token {
		r.versionMu.Unlock()
		r.mu.Unlock()
		return false
	}
	stale := make(map[string]struct{})
	for key := range r.wanted {
		if _, ok := desired[key]; !ok {
			delete(r.wanted, key)
			stale[key] = struct{}{}
		}
	}
	for key := range r.attached {
		if _, ok := desired[key]; !ok {
			stale[key] = struct{}{}
		}
	}
	for key := range desired {
		r.wanted[key] = struct{}{}
	}
	r.versionMu.Unlock()
	r.mu.Unlock()

	for _, key := range slices.Sorted(maps.Keys(stale)) {
		r.detachContainerIfUnwanted(key)
	}
	for _, key := range slices.Sorted(maps.Keys(desired)) {
		r.onContainerAddWanted(key, false)
	}
	return true
}

// detachContainerIfUnwanted completes snapshot pruning without deleting a key
// restored by a newer pod event or snapshot after the fast desired-state commit.
func (r *containerUprobeReconciler) detachContainerIfUnwanted(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if _, wanted := r.wanted[key]; wanted {
		return
	}
	r.detachContainerLocked(key)
}

// attachedCount returns the number of containers currently attached.
func (r *containerUprobeReconciler) attachedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attached)
}

// detachAll synchronously detaches every unique policy-spec/inode attachment
// and marks the reconciler closed so late adds cannot leak a sensor.
func (r *containerUprobeReconciler) detachAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advanceVersion()
	r.closed = true
	for _, probe := range r.probes {
		r.att.Detach(probe.key)
	}
	clear(r.probes)
	clear(r.attached)
	clear(r.wanted)
}
