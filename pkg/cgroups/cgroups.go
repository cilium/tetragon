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

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	/* Arbitrary values we only use this to track processes
	 * not to enforce nor set cgroup values
	 */
	SYSTEMD_V2_HIERARCHY = 1
	CPUSET_HIERARCHY     = 2
	PIDS_HIERARCHY       = 3
	MEMORY_HIERARCHY     = 4
	CGROUPV2_HIERARCHY   = 20
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
)

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

func CgroupNameFromCStr(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}
