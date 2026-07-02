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

// criResolveTimeout bounds the CRI ContainerStatus round-trip done during root
// resolution. Resolution runs on the pod-informer goroutine and the resync
// ticker, so a hung CRI socket must not block them indefinitely.
const criResolveTimeout = 5 * time.Second

// ricRootDirsSize bounds the container-id -> RootDir cache populated by the
// CreateContainer runtime hook. The hook fires for every container on the node,
// so the cache is bounded (LRU); resolvePathInContainer only looks up matched
// containers by id.
const ricRootDirsSize = 4096

// ricRootDirs maps a container id to the absolute host path of its root
// directory, as reported by the CreateContainer runtime hook (RootDir). It is
// the creation-time fallback used when CRI is disabled or has not resolved the
// container; CRI is tried first. On eviction (bounded LRU) a long-lived
// container can only be resolved via CRI, which is why CRI is recommended.
var ricRootDirs *lru.Cache[string, string]

func init() {
	var err error
	// lru.New only errors on a non-positive size, which is a constant here.
	ricRootDirs, err = lru.New[string, string](ricRootDirsSize)
	if err != nil {
		panic(err)
	}

	// Record container-id -> RootDir at container creation. Callbacks are
	// additive, so this runs alongside the other CreateContainer hooks.
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: func(_ context.Context, arg *rthooks.CreateContainerArg) error {
			recordContainerRootDir(arg)
			return nil
		},
	})
}

// recordContainerRootDir records the CreateContainer RootDir keyed by container
// id. It uses arg.ContainerID() (not arg.Req.ContainerID) so the key matches the
// stripped container id used for lookup and falls back to the cgroup-path-derived
// id when the runtime leaves the request field empty — the same accessor
// cgidmap's hook uses.
func recordContainerRootDir(arg *rthooks.CreateContainerArg) {
	rootDir := arg.Req.GetRootDir()
	// RootDir is later opened as the container root; require an absolute path so a
	// malformed/relative value cannot redirect resolution (defense in depth — the
	// hook socket is already access-controlled).
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
// container's root, from an authoritative runtime source, trying in order:
//  1. a container process resolved into procFS's PID namespace ->
//     <procFS>/<hostPID>/root (reached via the agent's host-procfs mount), and
//  2. the RootDir recorded by the CreateContainer runtime hook (host overlay
//     path; usable only when the agent has host-fs visibility).
//
// It returns the first source that yields an openable directory, or "" if
// neither is available (the caller skips the container and retries on the next
// pod event or resync). The process-cache host PID is intentionally not a source
// here: a host PID can be reused or race container teardown.
func resolveContainerRootDir(containerID string, procFS string) string {
	if containerID == "" {
		return ""
	}
	if option.Config.EnableCRI {
		if pid := containerHostPID(procFS, containerID); pid != 0 {
			root := filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "root")
			if dirOpenable(root) {
				return root
			}
		}
	}
	if rootDir, ok := ricRootDirs.Get(containerID); ok && rootDir != "" && dirOpenable(rootDir) {
		return rootDir
	}
	return ""
}

// containerHostPID returns the PID, in the PID namespace procFS belongs to (the
// host namespace Tetragon's events use), of a process that belongs to
// containerID. Any process in the container works: they share the mount
// namespace, so <procFS>/<pid>/root is the same container root for all of them.
// Returns 0 if no live process for the container is found in procFS.
//
// The CRI-reported PID is only directly usable when the runtime shares procFS's
// PID namespace — a flat deployment, where it is the host PID and is returned
// without a scan. When the runtime runs in a descendant PID namespace (e.g.
// kind, where containerd reports node-namespace PIDs while procFS is the host's
// /proc) that PID names a different/absent process in procFS, so it is
// translated by scanning procFS for the process whose cgroup names the
// container.
func containerHostPID(procFS, containerID string) uint32 {
	// Fast path: in a flat deployment the CRI PID is already a host PID. Verify
	// it actually belongs to this container (via its cgroup) so a coincidentally
	// same-numbered host process in a nested setup is not mistaken for it.
	if criPID := criContainerPID(containerID); criPID != 0 && pidInContainer(procFS, criPID, containerID) {
		return criPID
	}
	// Nested runtime: translate by finding the host process whose cgroup names
	// the container.
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
			return uint32(pid)
		}
	}
	return 0
}

// pidInContainer reports whether the process pid (as named in procFS) belongs to
// containerID, by checking whether its cgroup membership names the container. The
// container id appears in the cgroup path for the common runtimes (e.g.
// containerd's ".../cri-containerd-<id>.scope"), so a substring match identifies
// every process in the container regardless of the cgroup driver.
func pidInContainer(procFS string, pid uint32, containerID string) bool {
	b, err := os.ReadFile(filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return false // process gone, or cgroup not readable
	}
	return strings.Contains(string(b), containerID)
}

// criContainerPID returns the container's main-process PID as reported by the
// CRI runtime, or 0 on any error. The PID is in the runtime's PID namespace
// (the host's in a flat deployment, a descendant's under a nested runtime such
// as kind), so callers must resolve it into procFS's namespace before use — see
// containerHostPID. The CRI round-trip is bounded by criResolveTimeout so a hung
// socket cannot stall the caller.
func criContainerPID(containerID string) uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), criResolveTimeout)
	defer cancel()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		// Debug, not Warn: this is on the per-container resolve path driven by the
		// 10s resync, so a persistent failure would otherwise spam once per
		// container per tick.
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

// discoverExistingContainers lists the running containers known to the CRI
// runtime (joined with their pod sandboxes for namespace/labels) as the
// discovery source for containers that already exist when a policy loads and on
// the periodic resync. New containers do not depend on this — they arrive via
// pod events. Returns nil when CRI is disabled or the lookup fails (existing
// containers are then simply not discovered).
func discoverExistingContainers() []cri.RunningContainer {
	if !option.Config.EnableCRI {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), criResolveTimeout)
	defer cancel()
	cli, err := cri.GetClient(ctx)
	if err != nil {
		// Debug, not Warn: discovery runs on every 10s resync, so a persistent
		// CRI failure would spam. The CRI-disabled case is warned once per policy
		// load in registerResolvePathInContainer.
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI client unavailable for discovery",
			logfields.Error, err)
		return nil
	}
	containers, err := cri.RunningContainers(ctx, cli)
	if err != nil {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: CRI container discovery failed",
			logfields.Error, err)
		return nil
	}
	return containers
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
