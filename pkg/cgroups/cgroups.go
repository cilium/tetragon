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
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
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
	// Generic unset value that means undefined or not set
	CGROUP_UNSET_VALUE = 0

	// Max cgroup subsystems count that is used from BPF side
	// to define a max index for the default controllers on tasks.
	// For further documentation check BPF part.
	CGROUP_SUBSYS_COUNT = 15

	// The default hierarchy for cgroupv2
	CGROUP_DEFAULT_HIERARCHY = 0
)

type CgroupModeCode int

const (
	/* Cgroup Mode:
	 * https://systemd.io/CGROUP_DELEGATION/
	 * But this should work also for non-systemd environments: where
	 * only legacy or unified are available by default.
	 */
	CGROUP_UNDEF   CgroupModeCode = iota
	CGROUP_LEGACY  CgroupModeCode = 1
	CGROUP_HYBRID  CgroupModeCode = 2
	CGROUP_UNIFIED CgroupModeCode = 3
)

type DeploymentCode int

type deploymentEnv struct {
	id  DeploymentCode
	str string
}

const (
	// Deployment modes
	DEPLOY_UNKNOWN    DeploymentCode = iota
	DEPLOY_K8S        DeploymentCode = 1  // K8s deployment
	DEPLOY_CONTAINER  DeploymentCode = 2  // Container docker, podman, etc
	DEPLOY_SD_SERVICE DeploymentCode = 10 // Systemd service
	DEPLOY_SD_USER    DeploymentCode = 11 // Systemd user session
)

type cgroupController struct {
	id  uint32 // Hierarchy uniq ID
	idx uint32 // Cgroup SubSys index
	str string // Controller name
}

var (
	// Path where default cgroupfs is mounted
	defaultCgroupRoot = "/sys/fs/cgroup"

	/* Cgroupv1 controllers that we are interested in
	 * are usually the ones that are setup by systemd
	 * or other init programs.
	 */
	cgroupControllers = []cgroupController{
		// Memory first
		{str: "memory"},
		{str: "pids"},
	}

	cgroupv2Hierarchy = "0::"

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
	cgroupMode     CgroupModeCode
	cgroupFSPath   string

	// Cgroup Migration Path
	findMigPath       sync.Once
	cgrpMigrationPath string

	// Cgroup Tracking Hierarchy
	cgrpHierarchy    uint32
	cgrpHierarchyIdx uint32

	// Tetragon own Cgroup ID depends on Cgroup hierarchies
	tgCgrpID uint64

	deploymentMode DeploymentCode
)

func (code CgroupModeCode) String() string {
	return [...]string{
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}[code]
}

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

// DiscoverSubSysIds() Discover Cgroup SubSys IDs and indexes.
// of the corresponding controllers that we are interested
// in. We need this dynamic behavior since these controllers are
// compile config.
func DiscoverSubSysIds() error {
	path := filepath.Join(option.Config.ProcFS, "cgroups")
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	fscanner := bufio.NewScanner(file)
	fixed := false
	idx := 0
	for fscanner.Scan() {
		line := fscanner.Text()
		fields := strings.Fields(line)

		// No need to read enabled field as it can be enabled on
		// root without having a proper cgroup name to reflect that
		// or the controller is not active on the unified cgroupv2.
		for i, controller := range cgroupControllers {
			if fields[0] == controller.str {
				id, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					cgroupControllers[i].id = uint32(id)
					cgroupControllers[i].idx = uint32(idx - 1)
					fixed = true
				}
				// idx here is already > 1
				if (idx - 1) >= CGROUP_SUBSYS_COUNT {
					return fmt.Errorf("Cgroup default subsystem '%s' is indexed at high value '%d'", controller.str, idx-1)
				}
			}
		}
		idx++
	}

	if fixed == false {
		return fmt.Errorf("detect Cgroup controllers IDs from '%s' failed", path)
	}

	for _, controller := range cgroupControllers {
		if controller.id == 0 {
			continue
		}
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).Debugf("Cgroup Controller '%s' discovered with HierarchyID=%d and HierarchyIndex=%d", controller.str, controller.id, controller.idx)
	}

	return nil
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

	return fmt.Errorf("detect deployment mode failed, no match on Cgroup path '%s'", cgroupPath)
}

func getDeploymentMode() DeploymentCode {
	return deploymentMode
}

func SetCgrpHierarchyID(id uint32) {
	cgrpHierarchy = id
}

func SetCgrpHierarchyIdx(idx uint32) {
	cgrpHierarchyIdx = idx
}

// GetCgrpHierarchyID() returns the ID of the Cgroup hierarchy
// that is used to track process. This is used for Cgroupv1 as for
// Cgroupv2 we run in the default hierarchy.
func GetCgrpHierarchyID() uint32 {
	return cgrpHierarchy
}

// GetCgrpHierarchyIdx() returns the Index of the subsys
// or hierarchy to be used to track process.
func GetCgrpHierarchyIdx() uint32 {
	return cgrpHierarchyIdx
}

type FileHandle struct {
	Id uint64
}

func setTetragonCgroupID(cgroupPath string) error {
	if tgCgrpID != 0 {
		return nil
	}

	var fh FileHandle
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return err
	}

	err = binary.Read(bytes.NewBuffer(handle.Bytes()), binary.LittleEndian, &fh)
	if err != nil {
		return fmt.Errorf("decoding NameToHandleAt data failed: %v", err)
	}

	tgCgrpID = fh.Id

	return nil
}

// GetTetragonCgroupID() Returns own Tetragon Cgroup ID based on the cgroup path
// This can be controller cgroup ID in case of multiple hierarchies under cgroupv1
// which in this case depends on the selected hierarchy either 'memory' or 'pids'.
// Or the unique cgroup ID of the unified hierarchy under cgroupv2.
func GetTetragonCgroupID() uint64 {
	return tgCgrpID
}

// Validates cgroupPaths obtained from /proc/self/cgroup based on Cgroupv1
// and returns it on success
func getValidCgroupv1Path(cgroupPaths []string) (string, error) {
	for _, controller := range cgroupControllers {
		if controller.id == 0 {
			return "", fmt.Errorf("Cgroup controller '%s' is missing HierarchyID", controller.str)
		}

		for _, s := range cgroupPaths {
			if strings.Contains(s, fmt.Sprintf(":%s:", controller.str)) {
				idx := strings.Index(s, "/")
				path := s[idx+1:]
				cgroupPath := filepath.Join(cgroupFSPath, controller.str, path)
				finalpath := filepath.Join(cgroupPath, "cgroup.procs")
				_, err := os.Stat(finalpath)
				if err != nil {
					// Probably namespaced... run the deployment mode detection
					err = setDeploymentMode(path)
					if err == nil {
						mode := getDeploymentMode()
						if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
							// Cgroups are namespaced let's try again
							cgroupPath = filepath.Join(cgroupFSPath, controller.str)
							finalpath = filepath.Join(cgroupPath, "cgroup.procs")
							_, err = os.Stat(finalpath)
						}
					}
				}

				if err != nil {
					logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv1 path '%s'", finalpath)
					continue
				}

				// Run the deployment mode detection, fine to run it again.
				err = setDeploymentMode(path)
				if err != nil {
					logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warn("Failed to detect deployment from Cgroupv1 path")
					continue
				}

				err = setTetragonCgroupID(cgroupPath)
				if err != nil {
					logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warn("Failed to detect Cgroup ID from Cgroupv1 path")
					continue
				}

				SetCgrpHierarchyID(controller.id)
				SetCgrpHierarchyIdx(controller.idx)
				logger.GetLogger().WithFields(logrus.Fields{
					"Cgroupfs":              cgroupFSPath,
					"cgroup.path":           cgroupPath,
					"cgroup.controller":     controller.str,
					"cgroup.hierarchyID":    controller.id,
					"cgroup.hierarchyIndex": controller.idx,
				}).Info("Cgroupv1 hierarchy validated successfully")
				return finalpath, nil
			}
		}
	}

	return "", fmt.Errorf("could not validate Cgroupv1 hierarchies")
}

// Lookup Cgroupv2 active controllers and returns one that we support
func getCgroupv2Controller(cgroupPath string) (*cgroupController, error) {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return nil, fmt.Errorf("no active controllers from '%s'", file)
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"Cgroupfs":           cgroupFSPath,
		"cgroup.controllers": strings.Fields(activeControllers),
	}).Info("Cgroupv2 supported controllers detected successfully")

	for i, controller := range cgroupControllers {
		if strings.Contains(activeControllers, controller.str) {
			return &cgroupControllers[i], nil
		}
	}

	return nil, fmt.Errorf("Cgroupv2 no appropriate active controller")
}

// Validates cgroupPaths obtained from /proc/self/cgroup based on Cgroupv2
func getValidCgroupv2Path(cgroupPaths []string) (string, error) {
	for _, s := range cgroupPaths {
		if strings.Contains(s, cgroupv2Hierarchy) {
			idx := strings.Index(s, "/")
			path := s[idx+1:]
			cgroupPath := filepath.Join(cgroupFSPath, path)
			finalpath := filepath.Join(cgroupPath, "cgroup.procs")
			_, err := os.Stat(finalpath)
			if err != nil {
				// Namespaced ? let's force the check
				err = setDeploymentMode(path)
				if err == nil {
					mode := getDeploymentMode()
					if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
						// Cgroups are namespaced let's try again
						cgroupPath = cgroupFSPath
						finalpath = filepath.Join(cgroupPath, "cgroup.procs")
						_, err = os.Stat(finalpath)
					}
				}
			}

			if err != nil {
				logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv2 path '%s'", finalpath)
				break
			}

			// Run the deployment mode detection, fine to run it again.
			err = setDeploymentMode(path)
			if err != nil {
				logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warn("Failed to detect deployment from Cgroupv2 path")
				break
			}

			// This should not be necessary but there are broken setups out there
			// without cgroupv2 default bpf helpers
			controller, err := getCgroupv2Controller(cgroupPath)
			if err != nil {
				logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Failed to detect Cgroupv2 active controllers from path '%s'", cgroupPath)
				break
			}

			err = setTetragonCgroupID(cgroupPath)
			if err != nil {
				logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warn("Failed to detect Cgroup ID from Cgroupv2 path")
				break
			}

			SetCgrpHierarchyID(CGROUP_DEFAULT_HIERARCHY)
			SetCgrpHierarchyIdx(controller.idx)
			logger.GetLogger().WithFields(logrus.Fields{
				"Cgroupfs":              cgroupFSPath,
				"cgroup.path":           cgroupPath,
				"cgroup.controller":     controller.str,
				"cgroup.hierarchyID":    controller.id,
				"cgroup.hierarchyIndex": controller.idx,
			}).Info("Cgroupv2 hierarchy validated successfully")
			return finalpath, nil
		}
	}

	return "", fmt.Errorf("could not validate Cgroupv2 hierarchy")
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

func detectCgroupMode(cgroupfs string) (CgroupModeCode, error) {
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
//   - CGROUP_UNDEF: undefined
//   - CGROUP_LEGACY: Cgroupv1 legacy controllers
//   - CGROUP_HYBRID: Cgroupv1 and Cgroupv2 set up by systemd
//   - CGROUP_UNIFIED: Pure Cgroupv2 hierarchy
//
// Reference: https://systemd.io/CGROUP_DELEGATION/
func GetCgroupMode() (CgroupModeCode, error) {
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
			logger.GetLogger().WithFields(logrus.Fields{
				"Cgroupfs":   cgroupFSPath,
				"CgroupMode": cgroupMode.String(),
			}).Infof("Cgroup mode detection succeeded")
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return CGROUP_UNDEF, fmt.Errorf("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

func findMigrationPath(pid uint32) (string, error) {
	if cgrpMigrationPath != "" {
		return cgrpMigrationPath, nil
	}

	cgroupPaths, err := getPidCgroupPaths(pid)
	if err != nil {
		logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Unable to get Cgroup paths for pid=%d", pid)
		return "", err
	}

	mode, err := GetCgroupMode()
	if err != nil {
		return "", err
	}

	/* Run the validate and get cgroup migration path once
	 * as it triggers lot of checks.
	 */
	findMigPath.Do(func() {
		var err error
		switch mode {
		case CGROUP_LEGACY, CGROUP_HYBRID:
			cgrpMigrationPath, err = getValidCgroupv1Path(cgroupPaths)
		case CGROUP_UNIFIED:
			cgrpMigrationPath, err = getValidCgroupv2Path(cgroupPaths)
		default:
			err = fmt.Errorf("could not detect Cgroup Mode")
		}

		if err != nil {
			logger.GetLogger().WithField("Cgroupfs", cgroupFSPath).WithError(err).Warnf("Unable to find Cgroup migration path for pid=%d", pid)
		}
	})

	if cgrpMigrationPath == "" {
		return "", fmt.Errorf("could not detect Cgroup migration path for pid=%d", pid)
	}

	return cgrpMigrationPath, nil
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
		return uint32(mode), nil
	}

	// Let's call findMigrationPath in case to parse own cgroup
	// paths and detect the deployment mode.
	pid := os.Getpid()
	_, err := findMigrationPath(uint32(pid))
	if err != nil {
		return uint32(DEPLOY_UNKNOWN), err
	}

	mode = getDeploymentMode()
	return uint32(mode), nil
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
		return CGROUP_UNSET_VALUE, err
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

	return CGROUP_UNSET_VALUE, fmt.Errorf("could not detect Cgroup Mode")
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
