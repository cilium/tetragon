// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mountinfo"
)

var (
	// Path to where cgroup2 is mounted
	cgroup2Root = defaults.Cgroup2Dir
)

// mountFS mounts the BPFFS filesystem into the desired mapRoot directory.
func mountFS(root, kind string) error {
	mapRootStat, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(root, 0755); err != nil {
				return fmt.Errorf("unable to create %s mount directory: %s", kind, err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", root, err)

		}
	} else if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", root)
	}

	if err := syscall.Mount(root, root, kind, 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s %s: %s", root, kind, err)
	}
	return nil
}

// hasMultipleMounts checks whether the current mapRoot has only one mount.
func hasMultipleMounts() (bool, error) {
	num := 0

	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return false, err
	}

	for _, mountInfo := range mountInfos {
		if mountInfo.Root == "/" && mountInfo.MountPoint == mapRoot {
			num++
		}
	}

	return num > 1, nil
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
// given path.
func checkOrMountCustomLocation(bpfRoot string) error {
	SetMapRoot(bpfRoot)

	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}

	// Check whether the custom location has a BPFFS mount.
	mounted, bpffsInstance := mountinfo.IsMountFS(infos, mountinfo.FilesystemTypeBPFFS, bpfRoot)

	// If the custom location has no mount, let's mount BPFFS there.
	if !mounted {
		SetMapRoot(bpfRoot)
		return mountFS(mapRoot, mountinfo.FilesystemTypeBPFFS)
	}

	// If the custom location already has a mount with some other filesystem than
	// BPFFS, return the error.
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", bpfRoot)
	}

	logger.GetLogger().Debugf("Detected mounted BPF filesystem at %s", mapRoot)

	return nil
}

func checkOrMountDebugFSDefaultLocations() error {
	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}

	// Check whether /sys/fs/bpf has a BPFFS mount.
	mounted, debugfsInstance := mountinfo.IsMountFS(infos, mountinfo.FilesystemTypeDebugFS, debugFSRoot)

	// If /sys/kernel/debug is not mounted at all, we should mount
	// DebugFS there.
	if !mounted {
		return mountFS(debugFSRoot, mountinfo.FilesystemTypeDebugFS)
	}
	if !debugfsInstance {
		return fmt.Errorf("instance exists with othe type")
	}
	return nil
}

func checkOrMountCgroupDefaultLocation() error {
	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}

	// Check whether /run/tetragon/cgroup2 has a mount.
	mounted, cgroupInstance := mountinfo.IsMountFS(infos, mountinfo.FilesystemTypeCgroup2, cgroup2Root)

	// If /run/tetragon/cgroup2/ is not mounted at all, we should mount
	// cgroup2 there.
	if !mounted {
		_ = os.Mkdir(cgroup2Root, os.ModeDir)
		return mountFS(cgroup2Root, mountinfo.FilesystemTypeCgroup2)
	}
	if !cgroupInstance {
		return fmt.Errorf("instance exists with other type")
	}
	return nil
}

// checkOrMountDefaultLocations tries to check or mount the BPF filesystem in
// standard locations, which are:
// - /sys/fs/bpf
// - /run/cilium/bpffs
// There is a procedure of determining which directory is going to be used:
//  1. Checking whether BPFFS filesystem is mounted in /sys/fs/bpf.
//  2. If there is no mount, then mount BPFFS in /sys/fs/bpf and finish there.
//  3. If there is a BPFFS mount, finish there.
//  4. If there is a mount, but with the other filesystem, then it means that most
//     probably Cilium is running inside container which has mounted /sys/fs/bpf
//     from host, but host doesn't have proper BPFFS mount, so that mount is just
//     the empty directory. In that case, mount BPFFS under /run/cilium/bpffs.
func checkOrMountDefaultLocations() error {
	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}

	// Check whether /sys/fs/bpf has a BPFFS mount.
	mounted, bpffsInstance := mountinfo.IsMountFS(infos, mountinfo.FilesystemTypeBPFFS, mapRoot)

	// If /sys/fs/bpf is not mounted at all, we should mount
	// BPFFS there.
	if !mounted {
		return mountFS(mapRoot, mountinfo.FilesystemTypeBPFFS)
	}

	if !bpffsInstance {
		// If /sys/fs/bpf has a mount but with some other filesystem
		// than BPFFS, it means that Cilium is running inside container
		// and /sys/fs/bpf is not mounted on host. We should mount BPFFS
		// in /run/cilium/bpffs automatically. This will allow operation
		// of Cilium but will result in unmounting of the filesystem
		// when the pod is restarted. This in turn will cause resources
		// such as the connection tracking table of the BPF programs to
		// be released which will cause all connections into local
		// containers to be dropped. User is going to be warned.
		logger.GetLogger().Warnf("BPF filesystem is going to be mounted automatically "+
			"in %s. However, it probably means that Cilium is running "+
			"inside container and BPFFS is not mounted on the host. "+
			"for more information, see: https://cilium.link/err-bpf-mount",
			defaults.DefaultMapRootFallback,
		)
		SetMapRoot(defaults.DefaultMapRootFallback)

		infos, err = mountinfo.GetMountInfo()
		if err != nil {
			return err
		}

		cMounted, cBpffsInstance := mountinfo.IsMountFS(infos, mountinfo.FilesystemTypeBPFFS, mapRoot)
		if !cMounted {
			if err := mountFS(mapRoot, mountinfo.FilesystemTypeBPFFS); err != nil {
				return err
			}
		} else if !cBpffsInstance {
			logger.GetLogger().Warnf("%s is mounted but has a different filesystem than BPFFS", defaults.DefaultMapRootFallback)
		}
	}

	logger.GetLogger().Debugf("Detected mounted BPF filesystem at %s", mapRoot)

	return nil
}

func checkOrMountFS(bpfRoot string) error {
	if bpfRoot == "" {
		if err := checkOrMountDefaultLocations(); err != nil {
			return err
		}
	} else {
		if err := checkOrMountCustomLocation(bpfRoot); err != nil {
			return err
		}
	}

	multipleMounts, err := hasMultipleMounts()
	if err != nil {
		return err
	}
	if multipleMounts {
		return fmt.Errorf("multiple mount points detected at %s", mapRoot)
	}

	return nil
}

// CheckOrMountFS checks or mounts the BPF filesystem and then
// opens/creates/deletes all maps which have previously been scheduled to be
// opened/created/deleted.
func CheckOrMountFS(bpfRoot string) {
	mountOnce.Do(func() {
		if err := checkOrMountFS(bpfRoot); err != nil {
			logger.GetLogger().WithError(err).Warn("Unable to mount BPF filesystem")
		}
	})
}

func CheckOrMountDebugFS() error {
	return checkOrMountDebugFSDefaultLocations()
}

func CheckOrMountCgroup2() error {
	return checkOrMountCgroupDefaultLocation()
}

func ConfigureResourceLimits() error {
	return rlimit.RemoveMemlock()
}
