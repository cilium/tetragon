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

// rootResolver resolves a container id to "<procFS>/<pid>/root" for a process
// in it, or "" so the caller retries. Identifying the backing file reads the
// mount table beside that directory, so the shape matters. Injected to keep
// build-tagged CRI code out of here.
type rootResolver func(containerID string) string

// Containers, not attachments: replicas of one image share a single uprobe, so
// this bounds bookkeeping rather than the BPF programs an attach loads.
const maxContainersPerPolicy = 1000

// attacher loads and unloads the uprobe sensor behind one attachment; tests
// fake it. An attachment covers every container sharing the binary, so it must
// hold no per-container state. attachPath is the resolved binary, valid only
// while the caller holds it open.
type attacher interface {
	Attach(key, attachPath string) error
	Detach(key string)
}

// containerUprobeReconciler drives uprobe attach/detach per policy as
// containers come and go; created fresh on each policy load.
type containerUprobeReconciler struct {
	procFS      string // used to identify the file a uprobe really attaches to
	target      string // in-container binary path from the policy
	att         attacher
	resolveRoot rootResolver

	// mu guards the maps below, and the attach and detach themselves, so
	// concurrent add/del for the same key cannot double-attach. Resolving the
	// path and identifying the backing file deliberately run without it.
	mu       sync.Mutex
	attached map[string]string          // container key -> inode identity
	probes   map[string]*attachedUprobe // inode identity -> shared attachment
	wanted   map[string]struct{}        // keys desired (add seen, no delete yet)
	// closed is set by detachAll; further adds are no-ops so a late attach
	// cannot leak a container.
	closed    bool
	capWarned bool

	maxContainers int // maxContainersPerPolicy; lowered by tests
}

type attachedUprobe struct {
	// attachKey is the container key the attachment was made under, and the
	// one Detach must be given. Which container that is is arbitrary: whichever
	// reached the shared binary first.
	attachKey string
	refs      int // containers sharing this binary
}

func newContainerUprobeReconciler(procFS, target string, att attacher, resolveRoot rootResolver) *containerUprobeReconciler {
	return &containerUprobeReconciler{
		procFS:        procFS,
		target:        target,
		att:           att,
		resolveRoot:   resolveRoot,
		attached:      map[string]string{},
		probes:        map[string]*attachedUprobe{},
		wanted:        map[string]struct{}{},
		maxContainers: maxContainersPerPolicy,
	}
}

// admitLocked reports whether key can attach. Caller must hold r.mu.
func (r *containerUprobeReconciler) admitLocked(key string) bool {
	if r.closed {
		return false
	}
	if _, want := r.wanted[key]; !want {
		return false
	}
	if _, already := r.attached[key]; already {
		return false
	}
	if len(r.attached) >= r.maxContainers {
		if !r.capWarned {
			r.capWarned = true
			logger.GetLogger().Warn("uprobe resolvePathInContainer: per-policy container cap reached; "+
				"further matching containers will not be traced until others detach",
				"cap", r.maxContainers)
		}
		return false
	}
	return true
}

// Keys are "<podUID>/<containerID>". Both halves are "/"-free, so the
// separator is unambiguous.
func containerKey(podUID, containerID string) string {
	return podUID + "/" + containerID
}

func containerIDFromKey(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// markWanted records that the given containers should be attached, without
// resolving them. Resolving happens off the lock, so a delete arriving in
// between takes the same lock and wins over the pending attach.
func (r *containerUprobeReconciler) markWanted(keys ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	for _, key := range keys {
		r.wanted[key] = struct{}{}
	}
}

func (r *containerUprobeReconciler) attachWanted(key string) {
	r.mu.Lock()
	admit := r.admitLocked(key)
	r.mu.Unlock()
	if admit {
		r.resolveAndAttach(key)
	}
}

func (r *containerUprobeReconciler) onContainerAdd(key string) {
	r.markWanted(key)
	r.attachWanted(key)
}

// resolveAndAttach resolves the target off the lock, then attaches it under
// the lock. Any failure skips the container, retried on a later pod event.
func (r *containerUprobeReconciler) resolveAndAttach(key string) {
	root := r.resolveRoot(containerIDFromKey(key))
	if root == "" {
		logger.GetLogger().Debug("uprobe reconciler: skipping container with no resolvable root",
			"key", key)
		return
	}

	attachPath, closeFn, err := resolveBinaryUnderRoot(root, r.target)
	if err != nil {
		// Sidecar containers legitimately lack the target binary.
		if errors.Is(err, unix.ENOENT) || errors.Is(err, errNotRegularFile) || errors.Is(err, errTargetTooLarge) {
			logger.GetLogger().Debug("uprobe reconciler: path missing or unusable in container, skipping container",
				logfields.Error, err, "key", key, "root", root, "path", r.target)
		} else {
			logger.GetLogger().Warn("uprobe reconciler: failed to resolve container path, skipping container",
				logfields.Error, err, "key", key, "root", root, "path", r.target)
		}
		return
	}
	// Hold the fd until the attach completes so the inode cannot be swapped.
	defer closeFn()

	// Identifying the backing file reads the container's mount table and its
	// image layers, which needs no lock.
	fileID := backingFileID(r.procFS, root, r.target, attachPath)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.attachResolvedLocked(key, attachPath, fileID)
}

// attachResolvedLocked attaches one resolved binary for key. Containers
// sharing an inode share one uprobe and a reference count.
func (r *containerUprobeReconciler) attachResolvedLocked(key, attachPath, fileID string) {
	if !r.admitLocked(key) {
		return
	}

	probe := r.probes[fileID]
	if probe == nil {
		if err := r.att.Attach(key, attachPath); err != nil {
			// A container running a different build is an expected skip.
			if _, ok := errors.AsType[*DigestMismatchError](err); ok {
				logger.GetLogger().Debug("uprobe reconciler: container binary digest mismatch, skipping container",
					logfields.Error, err, "key", key)
			} else {
				logger.GetLogger().Warn("uprobe reconciler: failed to attach uprobe in container, skipping container",
					logfields.Error, err, "key", key)
			}
			return
		}
		probe = &attachedUprobe{attachKey: key}
		r.probes[fileID] = probe
	}
	probe.refs++
	r.attached[key] = fileID
}

func (r *containerUprobeReconciler) detachContainerLocked(key string) {
	fileID, ok := r.attached[key]
	if !ok {
		return
	}
	delete(r.attached, key)
	probe := r.probes[fileID]
	if probe == nil {
		return
	}
	if probe.refs--; probe.refs == 0 {
		r.att.Detach(probe.attachKey)
		delete(r.probes, fileID)
	}
}

func (r *containerUprobeReconciler) onContainerDel(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	delete(r.wanted, key)
	r.detachContainerLocked(key)
}

// onPodDel detaches by key prefix: delete events usually carry only terminated
// statuses, so they cannot enumerate what was attached.
func (r *containerUprobeReconciler) onPodDel(podUID string) {
	prefix := podUID + "/"
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
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

// detachAll detaches everything and closes the reconciler, so a late attach
// cannot leak a sensor.
func (r *containerUprobeReconciler) detachAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, probe := range r.probes {
		r.att.Detach(probe.attachKey)
	}
	clear(r.probes)
	clear(r.attached)
	clear(r.wanted)
}
