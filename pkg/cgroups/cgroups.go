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
	// Path where default cgroupfs is mounted
	defaultCgroupRoot = "/sys/fs/cgroup"

	/* Cgroupv1 controllers that we are interested in
	 * are usually the ones that are setup by systemd
	 * or other init programs.
	 */
	cgroupv1Hierarchies = []string{
		":cpuset:",
		":pids:",
		":memory:",
		":name=systemd:",
	}

	cgroupv2Hierarchy = "0::"

	cgroupModesStr = map[int]string{
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}

	readCgroupMode sync.Once
	cgroupMode     int
	cgroupFSPath   string

	readCgroupPaths sync.Once
	selfCgroupPaths []string

	findMigPathOnce sync.Once
	migrationPath   string
)

func CgroupFsMagicStr(magic uint64) string {
	if magic == unix.CGROUP2_SUPER_MAGIC {
		return "Cgroupv2"
	} else if magic == unix.CGROUP_SUPER_MAGIC {
		return "Cgroupv1"
	}

	return ""
}

func getValidCgroupv1Path(cgroupPaths []string) (string, error) {
	path := ""
	for _, v := range cgroupv1Hierarchies {
		for _, s := range cgroupPaths {
			if strings.Contains(s, v) {
				idx := strings.Index(s, "/")
				path = s[idx+1:]
				fields := strings.Split(s, ":")
				if fields[1] == "name=systemd" {
					fields[1] = "systemd"
				}

				path = filepath.Join(cgroupFSPath, fields[1], path, "cgroup.procs")
				_, err := os.Stat(path)
				if err != nil {
					logger.GetLogger().WithError(err).Warnf("failed to validate Cgroupv1 Path '%s'", path)
				} else {
					return path, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no valid Cgroupv1 controller to construct a proper Cgroup path")
}

func getValidCgroupv2Path(cgroupPaths []string) (string, error) {
	path := ""
	for _, s := range cgroupPaths {
		if strings.Contains(s, cgroupv2Hierarchy) {
			idx := strings.Index(s, "/")
			path = s[idx+1:]
			path = filepath.Join(cgroupFSPath, path, "cgroup.procs")
			_, err := os.Stat(path)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("failed to validate Cgroupv2 Path '%s'", path)
			} else {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("no valid Cgroupv2 path")
}

func getPidCgroupPaths(pidStr string) ([]string, error) {
	file := filepath.Join(option.Config.ProcFS, pidStr, "cgroup")
	readCgroupPaths.Do(func() {
		cgroups, err := ioutil.ReadFile(file)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("failed to read %s", file)
			return
		}

		selfCgroupPaths = strings.Split(strings.TrimSpace(string(cgroups)), "\n")
	})

	if len(selfCgroupPaths) == 0 {
		return nil, fmt.Errorf("failed to read %s", file)
	}

	return selfCgroupPaths, nil
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
		logger.GetLogger().WithError(err).Warnf("migrating pid=%s to %q failed", pidstr, path)
		return err
	}

	logger.GetLogger().Infof("Migrated Tetragon pid=%s to its cgroup %q", pidstr, path)
	return nil
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
		cgroupFSPath = defaultCgroupRoot
		cgroupMode, err = detectCgroupMode(cgroupFSPath)
		if err != nil {
			cgroupMode, err = detectCgroupMode(defaults.Cgroup2Dir)
			if err == nil {
				cgroupFSPath = defaults.Cgroup2Dir
			}
		}
		if cgroupMode != CGROUP_UNDEF {
			str, ok := cgroupModesStr[cgroupMode]
			if ok {
				logger.GetLogger().WithField("cgroupfs", cgroupFSPath).Infof("Running under Cgroup: %s", str)
			}
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return fmt.Errorf("could not detect Cgroup Mode")
	}

	return nil
}

func findMigrationPath() (string, error) {
	err := getCgroupMode()
	if err != nil {
		return "", err
	}

	findMigPathOnce.Do(func() {
		switch cgroupMode {
		case CGROUP_LEGACY, CGROUP_HYBRID:
			migrationPath, err = getValidCgroupv1Path(selfCgroupPaths)
		case CGROUP_UNIFIED:
			migrationPath, err = getValidCgroupv2Path(selfCgroupPaths)
		default:
			err = fmt.Errorf("could not detect Cgroup Mode")
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Unable to find Cgroup Path for Tetragon self detection")
		}
	})

	if migrationPath == "" {
		return migrationPath, fmt.Errorf("could not find Cgroup path for Tetragon self detection")
	}

	return migrationPath, nil
}

func MigrateSelfToSameCgrp() error {
	pid := os.Getpid()
	pidstr := fmt.Sprint(pid)

	_, err := getPidCgroupPaths(pidstr)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Unable to migrate Tetragon pid=%s to its own cgroup", pidstr)
		return err
	}

	path, err := findMigrationPath()
	if err != nil {
		return err
	}

	if err == nil {
		err = migratePidtoCgrp(path, pidstr)
	}

	return err
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
		logger.GetLogger().WithField("cgroupfs", cgroupFSPath).Info("Cgroup BPF helpers will run in raw Cgroup mode")
		return unix.CGROUP_SUPER_MAGIC, nil
	case CGROUP_UNIFIED:
		logger.GetLogger().WithField("cgroupfs", cgroupFSPath).Info("Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors")
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
