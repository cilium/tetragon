// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/rthooks"
)

// criResolveTimeout bounds the CRI round-trip during root resolution, which
// runs on the pod-informer goroutine and the resync ticker.
const criResolveTimeout = 5 * time.Second

// ricRootDirsSize bounds the container-id -> RootDir cache: the CreateContainer
// hook fires for every container on the node.
const ricRootDirsSize = 4096

// ricRootDirs maps container id -> RootDir host path recorded by the
// CreateContainer runtime hook; fallback when CRI cannot resolve the container.
var ricRootDirs *lru.Cache[string, string]

// ricHostPIDs caches container id -> host PID so resync retries skip the CRI
// round-trip or procFS scan. Hits are re-verified before use.
var ricHostPIDs *lru.Cache[string, uint32]

func init() {
	var err error
	// lru.New only errors on a non-positive size, which is a constant here.
	ricRootDirs, err = lru.New[string, string](ricRootDirsSize)
	if err != nil {
		panic(err)
	}
	ricHostPIDs, err = lru.New[string, uint32](ricRootDirsSize)
	if err != nil {
		panic(err)
	}

	// Callbacks are additive; this runs alongside the other CreateContainer hooks.
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: func(_ context.Context, arg *rthooks.CreateContainerArg) error {
			recordContainerRootDir(arg)
			return nil
		},
	})
}

// recordContainerRootDir records the CreateContainer RootDir keyed by
// arg.ContainerID(), the same stripped id used for lookup (and by cgidmap).
func recordContainerRootDir(arg *rthooks.CreateContainerArg) {
	rootDir := arg.Req.GetRootDir()
	// RootDir is later opened as the container root; reject relative or empty
	// values so a malformed one cannot redirect resolution.
	if rootDir == "" || !filepath.IsAbs(rootDir) {
		return
	}
	id, err := arg.ContainerID()
	if err != nil || id == "" {
		return
	}
	ricRootDirs.Add(id, rootDir)
}

// resolveContainerRootDir returns a directory the agent can open as the
// container's root: a container process's <procFS>/<hostPID>/root first, then
// the runtime-hook RootDir. Returns "" when neither is openable so the caller
// retries later. The PID is cgroup-verified; reuse before the caller reopens
// the path is inherent to any procfs+PID technique.
func resolveContainerRootDir(containerID string, procFS string) string {
	if containerID == "" {
		return ""
	}
	rootDir, hookRootKnown := ricRootDirs.Get(containerID)
	// A container process's root is in the right mount namespace even when the
	// hook's RootDir belongs to a runtime shim. Require CRI or a hook record so
	// unrelated pods cannot trigger a full procFS scan.
	if option.Config.EnableCRI || hookRootKnown {
		if pid := containerHostPID(procFS, containerID); pid != 0 {
			root := filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "root")
			if dirOpenable(root) {
				return root
			}
		}
	}
	if hookRootKnown && rootDir != "" {
		// RootDir is a host path; reach it through host PID 1's root since the
		// agent usually runs in its own mount namespace.
		hostRootDir := filepath.Join(procFS, "1", "root", strings.TrimPrefix(filepath.Clean(rootDir), string(filepath.Separator)))
		if dirOpenable(hostRootDir) {
			return hostRootDir
		}
		// Direct access for host deployments.
		if dirOpenable(rootDir) {
			return rootDir
		}
	}
	return ""
}

// containerHostPID returns the PID, in procFS's PID namespace, of any process
// in containerID, or 0. The CRI PID works in flat deployments; under a nested
// runtime (e.g. kind) procFS is scanned for a matching cgroup instead.
func containerHostPID(procFS, containerID string) uint32 {
	// Re-verify cached PIDs; re-resolve on a stale hit.
	if pid, ok := ricHostPIDs.Get(containerID); ok {
		if pidInContainer(procFS, pid, containerID) {
			return pid
		}
		ricHostPIDs.Remove(containerID)
	}
	// Flat deployment: the CRI PID is a host PID; verify it belongs to this
	// container so a same-numbered host process is not mistaken for it.
	if option.Config.EnableCRI {
		if criPID := criContainerPID(containerID); criPID != 0 && pidInContainer(procFS, criPID, containerID) {
			ricHostPIDs.Add(containerID, criPID)
			return criPID
		}
	}
	// Nested runtime: find a host process whose cgroup names the container.
	entries, err := os.ReadDir(procFS)
	if err != nil {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: reading procFS failed",
			logfields.Error, err, "procfs", procFS)
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a /proc/<pid> entry
		}
		if pidInContainer(procFS, uint32(pid), containerID) {
			ricHostPIDs.Add(containerID, uint32(pid))
			return uint32(pid)
		}
	}
	return 0
}

// pidInContainer reports whether pid belongs to containerID via its cgroup
// path, which names the container id for the common runtimes.
func pidInContainer(procFS string, pid uint32, containerID string) bool {
	if containerID == "" {
		// strings.Contains(s, "") is always true and would claim every process.
		return false
	}
	b, err := os.ReadFile(filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return false // process gone, or cgroup not readable
	}
	return strings.Contains(string(b), containerID)
}

// criContainerPID returns the container's main-process PID as reported by the
// CRI, or 0 on error. The PID is in the runtime's PID namespace.
func criContainerPID(containerID string) uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), criResolveTimeout)
	defer cancel()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		// Debug: runs per container each resync; Warn would spam.
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI client unavailable",
			logfields.Error, err)
		return 0
	}
	pid, err := cri.ContainerPID(ctx, cli, containerID)
	if err != nil {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI ContainerPID failed",
			logfields.Error, err, "container-id", containerID)
		return 0
	}
	return pid
}

// discoverExistingContainers lists the running containers known to the CRI.
// The bool reports whether the snapshot is authoritative: callers must not
// prune attachments after a disabled or failed CRI lookup.
func discoverExistingContainers() ([]cri.RunningContainer, bool) {
	if !option.Config.EnableCRI {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), criResolveTimeout)
	defer cancel()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		// Debug: runs on every resync; Warn would spam.
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI client unavailable for discovery",
			logfields.Error, err)
		return nil, false
	}
	containers, err := cri.RunningContainers(ctx, cli)
	if err != nil {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI container discovery failed",
			logfields.Error, err)
		return nil, false
	}
	return containers, true
}

// dirOpenable reports whether dir can be opened as a directory by the agent.
func dirOpenable(dir string) bool {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
