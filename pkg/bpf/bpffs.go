// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mountinfo"
)

var (
	// Path to where bpffs is mounted
	mapRoot = defaults.DefaultMapRoot

	// Prefix for all maps (default: tc/globals)
	mapPrefix = defaults.DefaultMapPrefix

	// Set to true on first get request to detect misorder
	lockedDown      = false
	once            sync.Once
	readMountInfo   sync.Once
	mountInfoPrefix string
)

func lockDown() {
	lockedDown = true
}

func SetMapRoot(path string) {
	if lockedDown {
		panic("SetMapRoot() call after MapRoot was read")
	}
	mapRoot = path
}

func GetMapRoot() string {
	once.Do(lockDown)
	return mapRoot
}

func SetMapPrefix(path string) {
	if lockedDown {
		panic("SetMapPrefix() call after MapPrefix was read")
	}
	mapPrefix = path
}

func MapPrefixPath() string {
	once.Do(lockDown)
	return filepath.Join(mapRoot, mapPrefix)
}

func mapPathFromMountInfo(name string) string {
	readMountInfo.Do(func() {
		mountInfos, err := mountinfo.GetMountInfo()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Could not get mount info for map root lookup")
		}

		for _, mountInfo := range mountInfos {
			if mountInfo.FilesystemType == mountinfo.FilesystemTypeBPFFS {
				mountInfoPrefix = filepath.Join(mountInfo.MountPoint, mapPrefix)
				return
			}
		}

		logger.GetLogger().Warn("Could not find BPF map root")
	})

	return filepath.Join(mountInfoPrefix, name)
}

// MapPath returns a path for a BPF map with a given name.
func MapPath(name string) string {
	return mapPathFromMountInfo(name)
}

// LocalMapName returns the name for a BPF map that is local to the specified ID.
func LocalMapName(name string, id uint16) string {
	return fmt.Sprintf("%s%05d", name, id)
}

// LocalMapPath returns the path for a BPF map that is local to the specified ID.
func LocalMapPath(name string, id uint16) string {
	return MapPath(LocalMapName(name, id))
}

// Environment returns a list of environment variables which are needed to make
// BPF programs and tc aware of the actual BPFFS mount path.
func Environment() []string {
	return append(
		os.Environ(),
		fmt.Sprintf("CILIUM_BPF_MNT=%s", GetMapRoot()),
		fmt.Sprintf("TC_BPF_MNT=%s", GetMapRoot()),
	)
}

var (
	mountOnce sync.Once
)
