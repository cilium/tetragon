// Copyright 2022 Authors of Tetragon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package cgroups

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	/* Arbitrary values we only use this to track Tetragon
	 * process, not to enforce nor set cgroup values
	 */
	SYSTEMD_V2_HIERARCHY = 1
	CPUSET_HIERARCHY     = 2
	PIDS_HIERARCHY       = 3
	MEMORY_HIERARCHY     = 4
	CGROUPV2_HIERARCHY   = 20
)

const (
	/* Cgroup Mode:
	 * https://systemd.io/CGROUP_DELEGATION/
	 * But this should work also for non-systemd environments: where
	 * only legacy or unified are available.
	 */
	CGROUP_UNDEF   = 0
	CGROUP_LEGACY  = 1
	CGROUP_HYBRID  = 2
	CGROUP_UNIFIED = 3
)

var (
	// Path to where cgroup2 is mounted
	cgroup2Root       = defaults.Cgroup2Dir
	defaultCgroupRoot = "/sys/fs/cgroup"

	matchedHierarchies = map[int]string{
		SYSTEMD_V2_HIERARCHY: ":name=systemd:",
		CPUSET_HIERARCHY:     ":cpuset:",
		PIDS_HIERARCHY:       ":pids:",
		MEMORY_HIERARCHY:     ":memory:",
		CGROUPV2_HIERARCHY:   "0::",
	}

	cgroupModesStr = map[int]string{
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}

	readCgroupMode sync.Once
	cgroupMode     int
	cgroupPath     string
)

func CgroupFsMagicStr(magic uint64) string {
	if magic == unix.CGROUP2_SUPER_MAGIC {
		return "Cgroupv2"
	} else if magic == unix.CGROUP_SUPER_MAGIC {
		return "Cgroupv1"
	}

	return ""
}

func getValidCgroupPath(hierarchy_idx int, cgroup string) string {
	_, ok := matchedHierarchies[hierarchy_idx]
	if !ok {
		return ""
	}

	idx := strings.Index(cgroup, "/")
	path := cgroup[idx+1:]

	switch hierarchy_idx {
	case CPUSET_HIERARCHY, PIDS_HIERARCHY, MEMORY_HIERARCHY:
		fields := strings.Split(cgroup, ":")
		path = filepath.Join(defaultCgroupRoot, fields[1], path, "cgroup.procs")
	case SYSTEMD_V2_HIERARCHY:
		path = filepath.Join(defaultCgroupRoot, "systemd", path, "cgroup.procs")
	case CGROUPV2_HIERARCHY:
		path = filepath.Join(cgroup2Root, path, "cgroup.procs")
	default:
		return ""
	}

	_, err := os.Stat(path)
	if err != nil {
		return ""
	}

	return path
}

func migratePidtoCgrp(path string, pidstr string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("open '%q' failed", path)
		return err
	}

	_, err = f.Write([]byte(pidstr))
	f.Close()
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("migrating pid=%s to '%q' failed", pidstr, path)
		return err
	}

	logger.GetLogger().Debugf("Migrated Tetragon pid=%s to its cgroup '%q'", pidstr, path)
	return nil
}

func MigratePidToSameCgrp(pid uint32) error {
	pidstr := fmt.Sprint(pid)
	cgroups, err := ioutil.ReadFile(filepath.Join(option.Config.ProcFS, pidstr, "cgroup"))
	if err != nil {
		return err
	}

	cgrpPaths := strings.Split(string(cgroups), "\n")
	for k, v := range matchedHierarchies {
		for _, s := range cgrpPaths {
			if strings.Contains(s, v) {
				path := getValidCgroupPath(k, s)
				if path != "" {
					return migratePidtoCgrp(path, pidstr)
				}
			}
		}
	}

	err = fmt.Errorf("no valid cgroup in /proc/%s/cgroup", pidstr)
	logger.GetLogger().WithError(err).Warn("Unable to migrate Tetragon pid to its own cgroup")

	return err
}

func detectCgroupMode(cgroupfs string) (int, error) {
	var st syscall.Statfs_t

	if err := syscall.Statfs(cgroupfs, &st); err != nil {
		return CGROUP_UNDEF, err
	}

	if st.Type == unix.CGROUP2_SUPER_MAGIC {
		return CGROUP_UNIFIED, nil
	} else if st.Type == unix.TMPFS_MAGIC {
		err := syscall.Statfs(filepath.Join(cgroupfs, "unified"), &st)
		if err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			return CGROUP_HYBRID, nil
		}
		return CGROUP_LEGACY, nil
	}

	err := fmt.Errorf("cgroupfs: '%s' is with the wrong fs type: %d", cgroupfs, st.Type)
	logger.GetLogger().WithError(err).WithField("cgroupfs", cgroupfs).Debug("could not detect Cgroup Mode")
	return CGROUP_UNDEF, err
}

func getCgroupMode() error {
	readCgroupMode.Do(func() {
		var err error
		cgroupPath = defaultCgroupRoot
		cgroupMode, err = detectCgroupMode(cgroupPath)
		if err != nil {
			cgroupMode, err = detectCgroupMode(defaults.Cgroup2Dir)
			if err == nil {
				cgroupPath = defaults.Cgroup2Dir
			}
		}
		if cgroupMode != CGROUP_UNDEF {
			str, ok := cgroupModesStr[cgroupMode]
			if ok {
				logger.GetLogger().WithField("cgroupfs", cgroupPath).Infof("Running under Cgroup: %s", str)
			}
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return fmt.Errorf("could not detect Cgroup Mode")
	}

	return nil
}

// Return the Cgroupfs v1 or v2 that will be used by bpf programs
func GetBpfCgroupFS() (uint64, error) {
	err := getCgroupMode()
	if err != nil {
		return CGROUP_UNDEF, err
	}

	switch cgroupMode {
	case CGROUP_LEGACY, CGROUP_HYBRID:
		/* In both legacy or Hybrid modes we switch to Cgroupv1 from bpf side. */
		logger.GetLogger().WithField("cgroupfs", cgroupPath).Info("Cgroup BPF helpers will run in raw Cgroup mode")
		return unix.CGROUP_SUPER_MAGIC, nil
	case CGROUP_UNIFIED:
		logger.GetLogger().WithField("cgroupfs", cgroupPath).Info("Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors")
		return unix.CGROUP2_SUPER_MAGIC, nil
	}

	return CGROUP_UNDEF, fmt.Errorf("could not detect Cgroup Mode")
}

func CgroupNameFromCStr(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}
