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

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
)

// The CRI round-trip runs on the pod-informer goroutine.
const criResolveTimeout = 5 * time.Second

// resolveContainerRootDir returns a directory the agent can open as the
// container's root: the root of a process running inside it. It returns "" when
// no such process is found, so the caller retries on a later pod event.
func resolveContainerRootDir(containerID, procFS string) string {
	if containerID == "" {
		return ""
	}
	pid := containerHostPID(procFS, containerID)
	if pid == 0 {
		return ""
	}
	root := filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10), "root")
	if !dirOpenable(root) {
		return ""
	}
	return root
}

// containerHostPID returns the PID, in procFS's PID namespace, of a process in
// containerID, or 0. Under a nested runtime (e.g. kind) the PID the CRI reports
// is not a host PID, so fall back to scanning procfs.
func containerHostPID(procFS, containerID string) uint32 {
	if option.Config.EnableCRI {
		if pid := criContainerPID(containerID); pid != 0 && pidInContainer(procFS, pid, containerID) {
			return pid
		}
	}
	entries, err := os.ReadDir(procFS)
	if err != nil {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: reading procFS failed",
			logfields.Error, err, "procfs", procFS)
		return 0
	}
	for _, e := range entries {
		pid, err := proc.GetProcPid(e.Name())
		if err != nil {
			continue // not a /proc/<pid> entry
		}
		if pidInContainer(procFS, uint32(pid), containerID) {
			return uint32(pid)
		}
	}
	return 0
}

// pidInContainer reports whether pid runs inside containerID: its cgroup path
// names the container and its root is not the host's. The feature needs a root
// that is not the host's, which also drops runtime helpers such as cri-o's
// conmon that share the container's cgroup but run in the host mount namespace.
func pidInContainer(procFS string, pid uint32, containerID string) bool {
	if containerID == "" {
		return false
	}
	pidDir := filepath.Join(procFS, strconv.FormatUint(uint64(pid), 10))
	b, err := os.ReadFile(filepath.Join(pidDir, "cgroup"))
	if err != nil {
		return false // process gone, or cgroup not readable
	}
	if !cgroupNamesContainer(string(b), containerID) {
		return false
	}
	return differentRoot(filepath.Join(pidDir, "root"), filepath.Join(procFS, "1", "root"))
}

// cgroupNamesContainer reports whether a cgroup file names containerID as a
// whole path component, bare or as a "<runtime>-<id>.scope" unit. Kept separate
// from procevents.LookupContainerId, which truncates the id; teach both when a
// runtime adds a naming form.
func cgroupNamesContainer(cgroup, containerID string) bool {
	suffix := "-" + containerID
	for line := range strings.SplitSeq(cgroup, "\n") {
		// "<hierarchy>:<controllers>:<path>"
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			continue
		}
		for comp := range strings.SplitSeq(fields[2], "/") {
			comp = strings.TrimSuffix(comp, ".scope")
			if comp == containerID || strings.HasSuffix(comp, suffix) {
				return true
			}
		}
	}
	return false
}

// differentRoot reports whether pidRoot is a different directory from
// hostRoot. Fail closed: a root that cannot be compared is not different.
func differentRoot(pidRoot, hostRoot string) bool {
	pi, err := os.Stat(pidRoot)
	if err != nil {
		return false
	}
	hi, err := os.Stat(hostRoot)
	if err != nil {
		return false
	}
	return !os.SameFile(pi, hi)
}

// criContainerPID returns the container's main-process PID as reported by the
// CRI, or 0 on error.
func criContainerPID(containerID string) uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), criResolveTimeout)
	defer cancel()
	cli, err := cri.GetClient(ctx)
	if err != nil {
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
