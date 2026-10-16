// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

var (
	errNotContainerProcess = errors.New("no process of the container has the CRI pid")
	errHostRootDir         = errors.New("runtime hook reported the host root as the container root")
	errNoParent            = errors.New("process has no parent")
	errParentChanged       = errors.New("process was reparented")
)

const criTimeout = 5 * time.Second

// containerRootFor takes the root a runtime hook reported, and asks CRI when
// there is none or it is unusable.
func containerRootFor(ctx context.Context, c policyfilter.ContainerChange) (*containerRoot, error) {
	procFS := option.Config.ProcFS
	if c.RootDir != "" {
		root, err := containerRootFromHook(procFS, c.RootDir)
		if err == nil {
			return root, nil
		}
		// The runtime's root may not be procFS's, as in a kind node.
		logger.GetLogger().Debug("uprobe resolvePathInContainer: runtime hook root unusable, asking CRI",
			logfields.Error, err, "container", c.ContainerID)
	}
	ctx, cancel := context.WithTimeout(ctx, criTimeout)
	defer cancel()
	return containerRootFromCRI(ctx, procFS, c.ContainerID)
}

// containerRoot is where a container's files resolve, and the mount table
// that lists its root filesystem.
type containerRoot struct {
	dir        string
	mountinfo  string
	mountPoint string // dir's mount point in mountinfo
	// layerRoot is the root of the runtime that mounted dir, where the
	// layer paths in mountinfo resolve.
	layerRoot string
	release   func()
}

// A runtime hook reports the root as a host path, so resolve it inside the
// host's root, where ".." and symlinks cannot leave it, and pin it. The host
// root itself is never a container's.
func containerRootFromHook(procFS, rootDir string) (*containerRoot, error) {
	hostFD, err := unix.Open(filepath.Join(procFS, "1", "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(hostFD)
	rootDir = filepath.Clean("/" + rootDir)
	fd, err := unix.Openat2(hostFD, "."+rootDir, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("opening runtime hook root %q: %w", rootDir, err)
	}
	var hostSt, rootSt unix.Stat_t
	if unix.Fstat(hostFD, &hostSt) != nil || unix.Fstat(fd, &rootSt) != nil ||
		(hostSt.Dev == rootSt.Dev && hostSt.Ino == rootSt.Ino) {
		unix.Close(fd)
		return nil, errHostRootDir
	}
	return &containerRoot{
		dir:        procSelfFDPath(fd),
		mountinfo:  filepath.Join(procFS, "1", "mountinfo"),
		mountPoint: rootDir,
		layerRoot:  filepath.Join(procFS, "1", "root"),
		release:    func() { unix.Close(fd) },
	}, nil
}

// containerRootFromCRI reaches the root through the container's init process.
// The open /proc/<pid> pins that process, so a reused PID fails the lookups
// rather than redirecting them.
func containerRootFromCRI(ctx context.Context, procFS, containerID string) (*containerRoot, error) {
	cli, err := cri.GetClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("CRI client: %w", err)
	}
	pid, err := cri.ContainerPid(ctx, cli, containerID)
	if err != nil {
		return nil, fmt.Errorf("CRI pid of container %s: %w", containerID, err)
	}
	fd, err := openContainerProcess(ctx, procFS, strconv.FormatUint(uint64(pid), 10), containerID)
	if err != nil {
		return nil, fmt.Errorf("pid %d: %w", pid, err)
	}
	root := pinnedContainerRoot(fd)
	root.layerRoot = filepath.Join(procFS, "1", "root")
	// The init's parent is normally the runtime's shim, whose root is the
	// runtime's even when procFS's is not, as in a kind node.
	if rootFD, err := openParentRoot(procFS, procSelfFDPath(fd)); err == nil {
		root.layerRoot = procSelfFDPath(rootFD)
		release := root.release
		root.release = func() {
			unix.Close(rootFD)
			release()
		}
	} else {
		logger.GetLogger().Debug("uprobe resolvePathInContainer: resolving image layers under the host root",
			logfields.Error, err, "container", containerID)
	}
	return root, nil
}

// openContainerProcess pins the container process the runtime knows as pid.
// A runtime one PID namespace below procFS's, such as a kind node, numbers it
// differently, so then find the process by the PID it has there.
func openContainerProcess(ctx context.Context, procFS, pid, containerID string) (int, error) {
	fd, directErr := openProcIf(filepath.Join(procFS, pid), containerID, "")
	if directErr == nil {
		return fd, nil
	}
	entries, err := os.ReadDir(procFS)
	if err != nil {
		return -1, fmt.Errorf("reading %s: %w", procFS, err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		if _, err := strconv.ParseUint(e.Name(), 10, 32); err != nil {
			continue
		}
		if fd, err := openProcIf(filepath.Join(procFS, e.Name()), containerID, pid); err == nil {
			return fd, nil
		}
	}
	return -1, errors.Join(errNotContainerProcess, directErr)
}

// openProcIf pins a /proc/<pid> directory whose process is in the container
// and, when nestedPid is set, has that PID one namespace below procFS's. The
// checks read through the pinned directory, so they describe that process.
func openProcIf(dir, containerID, nestedPid string) (int, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := checkContainerProcess(procSelfFDPath(fd), containerID, nestedPid); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func checkContainerProcess(pidDir, containerID, nestedPid string) error {
	if nestedPid != "" {
		status, err := os.ReadFile(filepath.Join(pidDir, "status"))
		if err != nil {
			return err
		}
		if !hasNestedPid(string(status), nestedPid) {
			return errNotContainerProcess
		}
	}
	cgroup, err := os.ReadFile(filepath.Join(pidDir, "cgroup"))
	if err != nil {
		return err
	}
	if !cgroupNamesContainer(string(cgroup), containerID) {
		return errNotContainerProcess
	}
	return nil
}

// hasNestedPid reports whether a status file's NSpid line, which lists the
// PIDs outermost first, gives pid one namespace below procFS's. Deeper
// namespaces are skipped, as a container can create those and pick PIDs.
func hasNestedPid(status, pid string) bool {
	for line := range strings.SplitSeq(status, "\n") {
		if pids, ok := strings.CutPrefix(line, "NSpid:"); ok {
			fields := strings.Fields(pids)
			return len(fields) > 1 && fields[1] == pid
		}
	}
	return false
}

// pinnedContainerRoot takes ownership of pidFD, an open /proc/<pid>.
func pinnedContainerRoot(pidFD int) *containerRoot {
	pidDir := procSelfFDPath(pidFD)
	return &containerRoot{
		dir:        filepath.Join(pidDir, "root"),
		mountinfo:  filepath.Join(pidDir, "mountinfo"),
		mountPoint: "/",
		release:    func() { unix.Close(pidFD) },
	}
}

// openParentRoot pins the root of the parent of the process at pidDir.
func openParentRoot(procFS, pidDir string) (int, error) {
	ppid, err := parentPid(pidDir)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open(filepath.Join(procFS, ppid, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	// A parent that exited before the open would have left the process
	// reparented, so an unchanged parent PID means fd is that parent's root.
	if again, err := parentPid(pidDir); err != nil || again != ppid {
		unix.Close(fd)
		return -1, errParentChanged
	}
	return fd, nil
}

func parentPid(pidDir string) (string, error) {
	status, err := os.ReadFile(filepath.Join(pidDir, "status"))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if ppid, ok := strings.CutPrefix(line, "PPid:"); ok {
			if ppid = strings.TrimSpace(ppid); ppid != "" && ppid != "0" {
				return ppid, nil
			}
		}
	}
	return "", errNoParent
}

// cgroupNamesContainer reports whether a cgroup file names containerID as a
// whole path component, bare or as a "<runtime>-<id>.scope" unit.
func cgroupNamesContainer(cgroup, containerID string) bool {
	suffix := "-" + containerID
	for line := range strings.SplitSeq(cgroup, "\n") {
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
