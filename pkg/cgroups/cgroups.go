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
	"github.com/sirupsen/logrus"
)

const (
	/* Cgroup Mode:
	 * https://systemd.io/CGROUP_DELEGATION/
	 * But this should work also for non-systemd environments: where
	 * only legacy or unified are available by default.
	 */
	CGROUP_UNDEF   = 0
	CGROUP_LEGACY  = 1
	CGROUP_HYBRID  = 2
	CGROUP_UNIFIED = 3
)

type deploymentEnv struct {
	id  uint32
	str string
}

const (
	// Deployment modes
	DEPLOY_UNKNOWN    = 0
	DEPLOY_K8S        = 1  // K8s deployment
	DEPLOY_CONTAINER  = 2  // Container docker, podman, etc
	DEPLOY_SD_SERVICE = 10 // Systemd service
	DEPLOY_SD_USER    = 11 // Systemd user session
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

	/* Ordered from nested to top cgroup parents
	 * For k8s we check also config k8s flags.
	 */
	deployments = []deploymentEnv{
		{id: DEPLOY_K8S, str: "kube"},
		{id: DEPLOY_CONTAINER, str: "docker"},
		{id: DEPLOY_CONTAINER, str: "podman"},
		{id: DEPLOY_CONTAINER, str: "libpod"},
		{id: DEPLOY_SD_SERVICE, str: "system.slice"},
		{id: DEPLOY_SD_USER, str: "user.slice"},
	}

	readCgroupMode sync.Once
	cgroupMode     int
	cgroupFSPath   string

	deploymentMode uint32
)

type DeploymentCode int

func (op DeploymentCode) String() string {
	return [...]string{
		DEPLOY_UNKNOWN:    "unknown",
		DEPLOY_K8S:        "Kubernetes",
		DEPLOY_CONTAINER:  "Container",
		DEPLOY_SD_SERVICE: "systemd service",
		DEPLOY_SD_USER:    "systemd user session",
	}[op]
}

// CgroupFsMagicStr() Returns "Cgroupv2" or "Cgroupv1" based on passed magic.
func CgroupFsMagicStr(magic uint64) string {
	if magic == unix.CGROUP2_SUPER_MAGIC {
		return "Cgroupv2"
	} else if magic == unix.CGROUP_SUPER_MAGIC {
		return "Cgroupv1"
	}

	return ""
}

func setDeploymentMode(cgroupPath string) error {
	if deploymentMode != DEPLOY_UNKNOWN {
		return nil
	}

	if option.Config.EnableK8s == true {
		deploymentMode = DEPLOY_K8S
		return nil
	}

	if cgroupPath == "" {
		// Probably namespaced
		deploymentMode = DEPLOY_CONTAINER
		return nil
	}

	for _, d := range deployments {
		if strings.Contains(cgroupPath, d.str) {
			deploymentMode = d.id
			return nil
		}
	}

	// Last operation fallback
	if cgroupPath == "/" {
		deploymentMode = DEPLOY_CONTAINER
		return nil
	}

	return fmt.Errorf("detect deployment mode failed no match for Cgroup Path '%s'", cgroupPath)
}

func getDeploymentMode() uint32 {
	return deploymentMode
}

// Validates cgroupPaths obtained from /proc/self/cgroup based on Cgroupv1
func getValidCgroupv1Path(cgroupPaths []string) (string, error) {
	for _, v := range cgroupv1Hierarchies {
		for _, s := range cgroupPaths {
			if strings.Contains(s, v) {
				idx := strings.Index(s, "/")
				path := s[idx+1:]
				// Get controllers
				fields := strings.Split(s, ":")
				if fields[1] == "name=systemd" {
					fields[1] = "systemd"
				}

				finalpath := filepath.Join(cgroupFSPath, fields[1], path, "cgroup.procs")
				_, err := os.Stat(finalpath)
				if err != nil {
					// Probably namespaced... run the deployment mode detection
					err = setDeploymentMode(path)
					if err == nil {
						mode := getDeploymentMode()
						if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
							// Cgroups are namespaced let's try again
							finalpath = filepath.Join(cgroupFSPath, fields[1], "cgroup.procs")
							_, err = os.Stat(finalpath)
						}
					}
				}
				if err == nil {
					// Run the deployment mode detection, fine to run it again.
					err = setDeploymentMode(path)
				}
				if err != nil {
					logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv1 Path '%s'", finalpath)
				} else {
					return finalpath, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no valid Cgroupv1 controller path")
}

// Validates cgroupPaths obtained from /proc/self/cgroup based on Cgroupv2
func getValidCgroupv2Path(cgroupPaths []string) (string, error) {
	for _, s := range cgroupPaths {
		if strings.Contains(s, cgroupv2Hierarchy) {
			idx := strings.Index(s, "/")
			path := s[idx+1:]
			finalpath := filepath.Join(cgroupFSPath, path, "cgroup.procs")
			_, err := os.Stat(finalpath)
			if err != nil {
				// Namespaced ? let's force the check
				err = setDeploymentMode(path)
				if err == nil {
					mode := getDeploymentMode()
					if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
						// Cgroups are namespaced let's try again
						finalpath = filepath.Join(cgroupFSPath, "cgroup.procs")
						_, err = os.Stat(finalpath)
					}
				}
			}
			if err == nil {
				// Run the deployment mode detection, fine to run it again.
				err = setDeploymentMode(path)
			}
			if err != nil {
				logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv2 Path '%s'", finalpath)
			} else {
				return finalpath, nil
			}
		}
	}

	return "", fmt.Errorf("no valid Cgroupv2 path")
}

func getPidCgroupPaths(pid uint32) ([]string, error) {
	file := filepath.Join(option.Config.ProcFS, fmt.Sprint(pid), "cgroup")

	cgroups, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", file, err)
	}

	if len(cgroups) == 0 {
		return nil, fmt.Errorf("no entry from %s", file)
	}

	return strings.Split(strings.TrimSpace(string(cgroups)), "\n"), nil
}

func migratePidtoCgrp(path string, pid uint32) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Open file %q failed", path)
		return err
	}

	_, err = f.Write([]byte(fmt.Sprint(pid)))
	f.Close()
	if err != nil {
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Migrating pid=%d to %q failed", pid, path)
		return err
	}

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

	return CGROUP_UNDEF, fmt.Errorf("wrong type '%d' for cgroupfs '%s'", st.Type, cgroupfs)
}

// GetCgroupMode() Returns the current Cgroup mode that is applied to the system
// This applies to systemd and non-systemd machines, possible values:
//  - CGROUP_UNDEF: undefined
//  - CGROUP_LEGACY: Cgroupv1 legacy controllers
//  - CGROUP_HYBRID: Cgroupv1 and Cgroupv2 set up by systemd
//  - CGROUP_UNIFIED: Pure Cgroupv2 hierarchy
// Reference: https://systemd.io/CGROUP_DELEGATION/
func GetCgroupMode() (int, error) {
	readCgroupMode.Do(func() {
		var err error
		cgroupFSPath = defaultCgroupRoot
		cgroupMode, err = detectCgroupMode(cgroupFSPath)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("Cgroupfs", cgroupFSPath).Debug("Could not detect Cgroup Mode")
			cgroupMode, err = detectCgroupMode(defaults.Cgroup2Dir)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("Cgroupfs", defaults.Cgroup2Dir).Debug("Could not detect Cgroup Mode")
			} else {
				cgroupFSPath = defaults.Cgroup2Dir
			}
		}
		if cgroupMode != CGROUP_UNDEF {
			str, ok := cgroupModesStr[cgroupMode]
			if ok {
				logger.GetLogger().WithFields(logrus.Fields{
					"Cgroupfs":   cgroupFSPath,
					"CgroupMode": str,
				}).Infof("Cgroup mode detection succeeded")
			}
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return CGROUP_UNDEF, fmt.Errorf("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

func findMigrationPath(pid uint32) (string, error) {
	cgroupPaths, err := getPidCgroupPaths(pid)
	if err != nil {
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Unable to get Cgroup paths for pid=%d", pid)
		return "", err
	}

	mode, err := GetCgroupMode()
	if err != nil {
		return "", err
	}

	var mig string
	switch mode {
	case CGROUP_LEGACY, CGROUP_HYBRID:
		mig, err = getValidCgroupv1Path(cgroupPaths)
	case CGROUP_UNIFIED:
		mig, err = getValidCgroupv2Path(cgroupPaths)
	default:
		err = fmt.Errorf("could not detect Cgroup Mode")
	}

	if err != nil {
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Unable to find Cgroup migration path for pid=%d", pid)
		return "", err
	}

	return mig, err
}

func MigrateSelfToSameCgrp() error {
	pid := os.Getpid()

	path, err := findMigrationPath(uint32(pid))
	if err != nil {
		return err
	}

	err = migratePidtoCgrp(path, uint32(pid))
	if err != nil {
		return err
	}

	logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).Infof("Migrated Tetragon pid=%d to its cgroup %q", pid, path)
	return nil
}

func detectDeploymentMode() (uint32, error) {
	mode := getDeploymentMode()
	if mode != DEPLOY_UNKNOWN {
		return mode, nil
	}

	// Let's call findMigrationPath in case to
	// get the Deployment Mode.
	pid := os.Getpid()
	_, err := findMigrationPath(uint32(pid))
	if err != nil {
		return DEPLOY_UNKNOWN, err
	}

	return getDeploymentMode(), nil
}

func DetectDeploymentMode() (uint32, error) {
	mode, err := detectDeploymentMode()
	if err != nil {
		return mode, err
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"Cgroupfs":       cgroupFSPath,
		"DeploymentMode": DeploymentCode(mode).String(),
	}).Info("Deployment mode detection succeeded")

	return mode, nil
}

// Return the Cgroupfs v1 or v2 that will be used by bpf programs
func GetBpfCgroupFS() (uint64, error) {
	mode, err := GetCgroupMode()
	if err != nil {
		return CGROUP_UNDEF, err
	}

	switch mode {
	case CGROUP_LEGACY, CGROUP_HYBRID:
		/* In both legacy or Hybrid modes we switch to Cgroupv1 from bpf side. */
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).Info("Cgroup BPF helpers will run in raw Cgroup mode")
		return unix.CGROUP_SUPER_MAGIC, nil
	case CGROUP_UNIFIED:
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).Info("Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors")
		return unix.CGROUP2_SUPER_MAGIC, nil
	}

	return CGROUP_UNDEF, fmt.Errorf("could not detect Cgroup Mode")
}

// CgroupNameFromCstr() Returns a Golang string from the passed C language format string.
func CgroupNameFromCStr(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}
