// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"errors"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// rootResolver resolves a container's root directory (a path the agent can open)
// from an authoritative runtime source — CRI first, then the CreateContainer
// runtime hook (RootDir) — returning "" when neither can resolve the container
// yet (the caller skips and retries). It is
// injected into the reconciler (the !nok8s build supplies the real resolver,
// tests supply a fake), so the reconciler itself stays free of build-tagged
// CRI/rthook code. A nil resolver resolves nothing.
type rootResolver func(containerID string, procFS string) string

// defaultMaxContainersPerPolicy bounds how many containers a single
// resolvePathInContainer policy will attach a uprobe in. Each attached container
// loads its own BPF program and maps, so an over-broad podSelector in a dense
// cluster could otherwise exhaust kernel resources. Containers beyond the cap
// are skipped with a warning.
const defaultMaxContainersPerPolicy = 1000

// ricTarget is one resolvePathInContainer uprobe's in-container binary path to
// resolve. btfPath, if set, is always resolved from the agent namespace (not
// in-container), so it is not carried here.
type ricTarget struct {
	path string // binary path inside the container
}

// resolvedUprobe is a ricTarget resolved inside a container: an inode-pinned
// handle the agent can open. Index-aligned with the policy's RIC uprobes.
type resolvedUprobe struct {
	attachPath string // resolved binary path (e.g. /proc/self/fd/N)
}

// Attacher attaches and detaches the per-container uprobe sensor (all of a
// policy's RIC uprobes for one container) for a given key. The real
// implementation builds and Load()s a per-container sensor and Unload()s it on
// Detach; tests provide a fake. key uniquely identifies the attach unit.
type Attacher interface {
	// Attach attaches the resolved uprobes for the given key. Implementations
	// should be idempotent for a repeated key.
	Attach(key string, resolved []resolvedUprobe) error
	// Detach removes the uprobes previously attached for key. It is a no-op if
	// key was never attached.
	Detach(key string)
}

// containerUprobeReconciler tracks which containers currently have the uprobe
// attached and drives attach/detach as containers come and go. It is the
// per-policy unit for a resolvePathInContainer uprobe, created fresh on each
// policy load.
//
// The reconciler holds no BPF state itself; it resolves the in-container path
// and delegates the actual attach/detach to an Attacher. This keeps the logic
// unit-testable without a kernel.
type containerUprobeReconciler struct {
	procFS        string
	targets       []ricTarget // in-container paths, index-aligned with the RIC uprobes
	att           Attacher
	resolveRoot   rootResolver // resolves a container id to an openable root dir
	maxContainers int

	// mu serializes the whole attach/detach for a container (not just the
	// attached map): onContainerAdd and onContainerDel for the same key can be
	// driven concurrently (informer goroutine vs the snapshot goroutine), so
	// the resolve+Attach and the Detach must be atomic with the bookkeeping to
	// avoid a double-attach or a detach racing an in-flight attach.
	mu       sync.Mutex
	attached map[string]struct{} // keys currently attached
	wanted   map[string]struct{} // keys actively desired (add received, no delete yet)
	// closed is set by detachAll (policy removal). Once closed, further adds are
	// no-ops, so a snapshot goroutine still running after unregister cannot
	// attach (and leak) a container.
	closed bool
}

func newContainerUprobeReconciler(procFS string, targets []ricTarget, att Attacher, resolveRoot rootResolver) *containerUprobeReconciler {
	return &containerUprobeReconciler{
		procFS:        procFS,
		targets:       targets,
		att:           att,
		resolveRoot:   resolveRoot,
		maxContainers: defaultMaxContainersPerPolicy,
		attached:      map[string]struct{}{},
		wanted:        map[string]struct{}{},
	}
}

// containerRoot returns a directory the agent can open as the keyed container's
// root, via the injected resolver. Returns "" when no root can be determined
// yet (resolver unset, or neither the runtime hook nor CRI resolves it).
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

// onContainerAdd resolves every RIC uprobe's in-container path for a container
// selected by the policy and attaches them. key uniquely identifies the
// container (e.g. "<podID>/<containerID>"); the container id embedded in the
// key drives root resolution via the runtime hook / CRI (see rootResolver).
// Resolution is all-or-nothing per container: if any path (or BTF path) fails,
// the whole container is skipped and retried later. Failures are isolated to
// this container (other containers are unaffected).
func (r *containerUprobeReconciler) onContainerAdd(key string) {
	// Cheap pre-check: skip resolving (and any CRI round-trip) when already
	// attached or closed. The resync re-drives onContainerAdd for every matched
	// container, so this avoids repeated work; the attach below re-checks under
	// the lock to handle a concurrent add.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	if _, already := r.attached[key]; already {
		r.mu.Unlock()
		return
	}
	if len(r.attached) >= r.maxContainers {
		// Over the per-policy cap: skip before any CRI round-trip or filesystem
		// resolve work, since the 10s resync re-drives this for every unattached
		// matched container. Debug, not Warn: the resync would otherwise repeat
		// the log every interval once the cap is hit. Re-checked under the lock
		// after resolve, in case attached grew meanwhile.
		r.mu.Unlock()
		logger.GetLogger().Debug("uprobe reconciler: per-policy container cap reached, skipping container",
			"key", key, "cap", r.maxContainers)
		return
	}
	r.wanted[key] = struct{}{}
	r.mu.Unlock()

	root := r.containerRoot(key)
	if root == "" {
		// No container root could be resolved yet: the runtime hook has not
		// recorded a RootDir for this container and CRI is off or could not
		// resolve it. Skip; retried on a later pod update or resync.
		logger.GetLogger().Debug("uprobe reconciler: skipping container with no resolvable root",
			"key", key)
		return
	}

	// Resolve all targets under the container root, holding every fd open until
	// the attach completes so the inodes the uprobes attach to are validated.
	var closers []func()
	defer func() {
		for _, f := range closers {
			f()
		}
	}()
	resolve := func(p string) (string, bool) {
		rp, closeFn, err := resolveBinaryUnderRoot(root, p)
		if err != nil {
			// A path that simply is not present in this container is expected for
			// sidecar/helper containers in a matched pod that lack the target
			// binary; log it at Debug so the 10s resync does not spam Warn. Other
			// failures (permission, resolve errors) stay at Warn.
			if errors.Is(err, unix.ENOENT) {
				logger.GetLogger().Debug("uprobe reconciler: path not present in container, skipping container",
					logfields.Error, err, "key", key, "root", root, "path", p)
			} else {
				logger.GetLogger().Warn("uprobe reconciler: failed to resolve container path, skipping container",
					logfields.Error, err, "key", key, "root", root, "path", p)
			}
			return "", false
		}
		closers = append(closers, closeFn)
		return rp, true
	}

	resolved := make([]resolvedUprobe, len(r.targets))
	for i, t := range r.targets {
		ap, ok := resolve(t.path)
		if !ok {
			return
		}
		resolved[i] = resolvedUprobe{attachPath: ap}
	}

	// Hold the lock across the attach so a concurrent add for the same key
	// cannot both pass the "already attached" check and double-attach, and so a
	// concurrent detach cannot race the attach. Attaching is not on a hot path.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if _, active := r.wanted[key]; !active {
		logger.GetLogger().Debug("uprobe reconciler: skipping container attach, no longer wanted",
			"key", key)
		return
	}
	if _, already := r.attached[key]; already {
		return
	}
	if len(r.attached) >= r.maxContainers {
		// Debug, not Warn: the periodic resync retries over-cap containers, so a
		// Warn here would repeat every resync interval once the cap is hit.
		logger.GetLogger().Debug("uprobe reconciler: per-policy container cap reached, skipping container",
			"key", key, "cap", r.maxContainers)
		return
	}

	if err := r.att.Attach(key, resolved); err != nil {
		logger.GetLogger().Warn("uprobe reconciler: failed to attach uprobe in container, skipping container",
			logfields.Error, err, "key", key)
		return
	}
	r.attached[key] = struct{}{}
}

// onContainerDel detaches the uprobe for a container that has gone away. The
// detach happens under the lock so it cannot interleave with an attach for the
// same key. It runs on the informer/snapshot goroutines (off the sensor-manager
// collection lock), so calling into the manager here cannot deadlock.
func (r *containerUprobeReconciler) onContainerDel(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.wanted, key)
	if _, ok := r.attached[key]; !ok {
		return
	}
	delete(r.attached, key)
	r.att.Detach(key)
}

// attachedCount returns the number of containers currently attached.
func (r *containerUprobeReconciler) attachedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attached)
}

// detachAll detaches every container currently attached and marks the
// reconciler closed, so any later add (e.g. from a snapshot goroutine still
// running after the policy was removed) is a no-op and cannot leak a sensor.
// Used when the policy owning this reconciler is removed (disabled or deleted).
//
// The detach work runs on its own goroutine: detachAll is called from the
// sensor PostUnloadHook, which can run while the sensor manager holds its
// collection lock (RemoveAllSensors on shutdown). att.Detach re-enters the
// manager, so doing it synchronously here would deadlock. Running it
// asynchronously keeps PostUnloadHook from blocking on (or under) that lock; on
// shutdown the child sensors are torn down by RemoveAllSensors anyway, so the
// late Detach calls are harmless no-ops.
func (r *containerUprobeReconciler) detachAll() {
	go func() {
		r.mu.Lock()
		r.closed = true
		keys := make([]string, 0, len(r.attached))
		for k := range r.attached {
			keys = append(keys, k)
		}
		r.attached = map[string]struct{}{}
		r.wanted = map[string]struct{}{}
		r.mu.Unlock()

		for _, k := range keys {
			r.att.Detach(k)
		}
	}()
}
