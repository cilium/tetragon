// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package cgroups

import (
	"bufio"
	"bytes"
	"fmt"
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

type CgroupController struct {
	Id     uint32 // Hierarchy unique ID
	Idx    uint32 // Cgroup SubSys index
	Name   string // Controller name
	Active bool   // Will be set to true if controller is set and active
}

var (
	// Path where default cgroupfs is mounted
	defaultCgroupRoot = "/sys/fs/cgroup"

	/* Cgroup controllers that we are interested in
	 * are usually the ones that are setup by systemd
	 * or other init programs.
	 */
	CgroupControllers = []CgroupController{
		{Name: "memory"}, // Memory first
		{Name: "pids"},   // pids second
		{Name: "cpuset"}, // fallback
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

	detectDeploymentOnce sync.Once
	deploymentMode       DeploymentCode

	detectCgrpModeOnce sync.Once
	cgroupMode         CgroupModeCode

	detectCgroupFSOnce sync.Once
	cgroupFSPath       string
	cgroupFSMagic      uint64

	// Cgroup Migration Path
	findMigPath       sync.Once
	cgrpMigrationPath string

	// Cgroup Tracking Hierarchy
	cgrpHierarchy    uint32
	cgrpSubsystemIdx uint32
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

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// CgroupFsMagicStr() Returns "Cgroupv2" or "Cgroupv1" based on passed magic.
func CgroupFsMagicStr(magic uint64) string {
	if magic == unix.CGROUP2_SUPER_MAGIC {
		return "Cgroupv2"
	} else if magic == unix.CGROUP_SUPER_MAGIC {
		return "Cgroupv1"
	}

	return ""
}

func GetCgroupFSMagic() uint64 {
	return cgroupFSMagic
}

func GetCgroupFSPath() string {
	return cgroupFSPath
}

func parseCgroupSubSysIds(filePath string) error {
	var allcontrollers []string

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	fscanner := bufio.NewScanner(file)
	fixed := false
	idx := 0
	fscanner.Scan() // ignore first entry
	for fscanner.Scan() {
		line := fscanner.Text()
		fields := strings.Fields(line)

		allcontrollers = append(allcontrollers, fields[0])

		// No need to read enabled field as it can be enabled on
		// root without having a proper cgroup name to reflect that
		// or the controller is not active on the unified cgroupv2.
		for i, controller := range CgroupControllers {
			if fields[0] == controller.Name {
				/* We care only for the controllers that we want */
				if idx >= CGROUP_SUBSYS_COUNT {
					/* Maybe some cgroups are not upstream? */
					return fmt.Errorf("Cgroup default subsystem '%s' is indexed at idx=%d higher than CGROUP_SUBSYS_COUNT=%d",
						fields[0], idx, CGROUP_SUBSYS_COUNT)
				}

				id, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					CgroupControllers[i].Id = uint32(id)
					CgroupControllers[i].Idx = uint32(idx)
					CgroupControllers[i].Active = true
					fixed = true
				} else {
					logger.GetLogger().WithFields(logrus.Fields{
						"cgroup.fs":              cgroupFSPath,
						"cgroup.controller.name": controller.Name,
					}).WithError(err).Warnf("parsing controller line from '%s' failed", filePath)
				}
			}
		}
		idx++
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"cgroup.fs":          cgroupFSPath,
		"cgroup.controllers": fmt.Sprintf("[%s]", strings.Join(allcontrollers, " ")),
	}).Debugf("Cgroup available controllers")

	// Could not find 'memory', 'pids' nor 'cpuset' controllers, are they compiled in?
	if fixed == false {
		err = fmt.Errorf("detect cgroup controllers IDs from '%s' failed", filePath)
		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.fs": cgroupFSPath,
		}).WithError(err).Warnf("Cgroup controllers 'memory', 'pids' and 'cpuset' are missing")
		return err
	}

	for _, controller := range CgroupControllers {
		// Print again everything that is available or not
		if controller.Active {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.fs":                     cgroupFSPath,
				"cgroup.controller.name":        controller.Name,
				"cgroup.controller.hierarchyID": controller.Id,
				"cgroup.controller.index":       controller.Idx,
			}).Infof("Supported cgroup controller '%s' is active on the system", controller.Name)
		} else {
			// Warn with error
			err = fmt.Errorf("controller '%s' is not active", controller.Name)
			logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Supported cgroup controller '%s' is not active", controller.Name)
		}
	}

	return nil
}

// DiscoverSubSysIds() Discover Cgroup SubSys IDs and indexes.
// of the corresponding controllers that we are interested
// in. We need this dynamic behavior since these controllers are
// compile config.
func DiscoverSubSysIds() error {
	return parseCgroupSubSysIds(filepath.Join(option.Config.ProcFS, "cgroups"))
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

	// Last go through the deployments
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

func GetDeploymentMode() uint32 {
	return uint32(getDeploymentMode())
}

func GetCgroupMode() CgroupModeCode {
	return cgroupMode
}

func setCgrpHierarchyID(controller *CgroupController) {
	cgrpHierarchy = controller.Id
}

func setCgrp2HierarchyID() {
	cgrpHierarchy = CGROUP_DEFAULT_HIERARCHY
}

func setCgrpSubsystemIdx(controller *CgroupController) {
	cgrpSubsystemIdx = controller.Idx
}

// GetCgrpHierarchyID() returns the ID of the Cgroup hierarchy
// that is used to track processes. This is used for Cgroupv1 as for
// Cgroupv2 we run in the default hierarchy.
func GetCgrpHierarchyID() uint32 {
	return cgrpHierarchy
}

// GetCgrpSubsystemIdx() returns the Index of the subsys
// or hierarchy to be used to track processes.
func GetCgrpSubsystemIdx() uint32 {
	return cgrpSubsystemIdx
}

// GetCgrpControllerName() returns the name of the controller that is
// being used as fallback from the css to get cgroup information and
// track processes.
func GetCgrpControllerName() string {
	for _, controller := range CgroupControllers {
		if controller.Active && controller.Idx == cgrpSubsystemIdx {
			return controller.Name
		}
	}
	return ""
}

// Validates cgroupPaths obtained from /proc/self/cgroup based on Cgroupv1
// and returns it on success
func getValidCgroupv1Path(cgroupPaths []string) (string, error) {
	for _, controller := range CgroupControllers {
		// First lets go again over list of active controllers
		if controller.Active == false {
			logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).Debugf("Cgroup controller '%s' is not active", controller.Name)
			continue
		}

		for _, s := range cgroupPaths {
			if strings.Contains(s, fmt.Sprintf(":%s:", controller.Name)) {
				idx := strings.Index(s, "/")
				path := s[idx+1:]
				cgroupPath := filepath.Join(cgroupFSPath, controller.Name, path)
				finalpath := filepath.Join(cgroupPath, "cgroup.procs")
				_, err := os.Stat(finalpath)
				if err != nil {
					// Probably namespaced... run the deployment mode detection
					err = setDeploymentMode(path)
					if err == nil {
						mode := getDeploymentMode()
						if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
							// Cgroups are namespaced let's try again
							cgroupPath = filepath.Join(cgroupFSPath, controller.Name)
							finalpath = filepath.Join(cgroupPath, "cgroup.procs")
							_, err = os.Stat(finalpath)
						}
					}
				}

				if err != nil {
					logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv1 path '%s'", finalpath)
					continue
				}

				// Run the deployment mode detection last again, fine to rerun.
				err = setDeploymentMode(path)
				if err != nil {
					logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warn("Failed to detect deployment mode from Cgroupv1 path")
					continue
				}

				logger.GetLogger().WithFields(logrus.Fields{
					"cgroup.fs":                     cgroupFSPath,
					"cgroup.controller.name":        controller.Name,
					"cgroup.controller.hierarchyID": controller.Id,
					"cgroup.controller.index":       controller.Idx,
				}).Infof("Cgroupv1 controller '%s' will be used", controller.Name)

				setCgrpHierarchyID(&controller)
				setCgrpSubsystemIdx(&controller)
				logger.GetLogger().WithFields(logrus.Fields{
					"cgroup.fs":   cgroupFSPath,
					"cgroup.path": cgroupPath,
				}).Info("Cgroupv1 hierarchy validated successfully")
				return finalpath, nil
			}
		}
	}

	// Cgroupv1 hierarchy is not properly setup we can not support such systems,
	// reason should have been logged in above messages.
	return "", fmt.Errorf("could not validate Cgroupv1 hierarchies")
}

// Lookup Cgroupv2 active controllers and returns one that we support
func getCgroupv2Controller(cgroupPath string) (*CgroupController, error) {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return nil, fmt.Errorf("no active controllers from '%s'", file)
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"cgroup.fs":          cgroupFSPath,
		"cgroup.controllers": strings.Fields(activeControllers),
	}).Info("Cgroupv2 supported controllers detected successfully")

	for i, controller := range CgroupControllers {
		if controller.Active && strings.Contains(activeControllers, controller.Name) {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.fs":                     cgroupFSPath,
				"cgroup.controller.name":        controller.Name,
				"cgroup.controller.hierarchyID": controller.Id,
				"cgroup.controller.index":       controller.Idx,
			}).Infof("Cgroupv2 controller '%s' will be used as a fallback for the default hierarchy", controller.Name)
			return &CgroupControllers[i], nil
		}
	}

	// Cgroupv2 hierarchy does not have the appropriate controllers.
	// Maybe init system or any other component failed to prepare cgroups properly.
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
				logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Failed to validate Cgroupv2 path '%s'", finalpath)
				break
			}

			// This should not be necessary but there are broken setups out there
			// without cgroupv2 default bpf helpers
			controller, err := getCgroupv2Controller(cgroupPath)
			if err != nil {
				logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Failed to detect current Cgroupv2 active controller")
				break
			}

			// Run the deployment mode detection last again, fine to rerun.
			err = setDeploymentMode(path)
			if err != nil {
				logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warn("Failed to detect deployment mode from Cgroupv2 path")
				break
			}

			setCgrp2HierarchyID()
			setCgrpSubsystemIdx(controller)
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.fs":   cgroupFSPath,
				"cgroup.path": cgroupPath,
			}).Info("Cgroupv2 hierarchy validated successfully")
			return finalpath, nil
		}
	}

	// Cgroupv2 hierarchy is not properly setup we can not support such systems,
	// reason should have been logged in above messages.
	return "", fmt.Errorf("could not validate Cgroupv2 hierarchy")
}

func getPidCgroupPaths(pid uint32) ([]string, error) {
	file := filepath.Join(option.Config.ProcFS, fmt.Sprint(pid), "cgroup")

	cgroups, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", file, err)
	}

	if len(cgroups) == 0 {
		return nil, fmt.Errorf("no entry from %s", file)
	}

	return strings.Split(strings.TrimSpace(string(cgroups)), "\n"), nil
}

func findMigrationPath(pid uint32) (string, error) {
	if cgrpMigrationPath != "" {
		return cgrpMigrationPath, nil
	}

	cgroupPaths, err := getPidCgroupPaths(pid)
	if err != nil {
		logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Unable to get Cgroup paths for pid=%d", pid)
		return "", err
	}

	mode, err := DetectCgroupMode()
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
			logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).WithError(err).Warnf("Unable to find Cgroup migration path for pid=%d", pid)
		}
	})

	if cgrpMigrationPath == "" {
		return "", fmt.Errorf("could not detect Cgroup migration path for pid=%d", pid)
	}

	return cgrpMigrationPath, nil
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

// DetectCgroupMode() Returns the current Cgroup mode that is applied to the system
// This applies to systemd and non-systemd machines, possible values:
//   - CGROUP_UNDEF: undefined
//   - CGROUP_LEGACY: Cgroupv1 legacy controllers
//   - CGROUP_HYBRID: Cgroupv1 and Cgroupv2 set up by systemd
//   - CGROUP_UNIFIED: Pure Cgroupv2 hierarchy
//
// Reference: https://systemd.io/CGROUP_DELEGATION/
func DetectCgroupMode() (CgroupModeCode, error) {
	detectCgrpModeOnce.Do(func() {
		var err error
		cgroupFSPath = defaultCgroupRoot
		cgroupMode, err = detectCgroupMode(cgroupFSPath)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("cgroup.fs", cgroupFSPath).Debug("Could not detect Cgroup Mode")
			cgroupMode, err = detectCgroupMode(defaults.Cgroup2Dir)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("cgroup.fs", defaults.Cgroup2Dir).Debug("Could not detect Cgroup Mode")
			} else {
				cgroupFSPath = defaults.Cgroup2Dir
			}
		}
		if cgroupMode != CGROUP_UNDEF {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.fs":   cgroupFSPath,
				"cgroup.mode": cgroupMode.String(),
			}).Infof("Cgroup mode detection succeeded")
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return CGROUP_UNDEF, fmt.Errorf("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

func detectDeploymentMode() (DeploymentCode, error) {
	mode := getDeploymentMode()
	if mode != DEPLOY_UNKNOWN {
		return mode, nil
	}

	// Let's call findMigrationPath in case to parse own cgroup
	// paths and detect the deployment mode.
	pid := os.Getpid()
	_, err := findMigrationPath(uint32(pid))
	if err != nil {
		return DEPLOY_UNKNOWN, err
	}

	return getDeploymentMode(), nil
}

func DetectDeploymentMode() (uint32, error) {
	detectDeploymentOnce.Do(func() {
		mode, err := detectDeploymentMode()
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgroup.fs": cgroupFSPath,
			}).WithError(err).Warn("Detection of deployment mode failed")
			return
		}

		logger.GetLogger().WithFields(logrus.Fields{
			"cgroup.fs":       cgroupFSPath,
			"deployment.mode": DeploymentCode(mode).String(),
		}).Info("Deployment mode detection succeeded")
	})

	mode := getDeploymentMode()
	if mode == DEPLOY_UNKNOWN {
		return uint32(mode), fmt.Errorf("detect deployment mode failed, could not parse process cgroup paths")
	}

	return uint32(mode), nil
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// Return the Cgroupfs v1 or v2 that will be used by bpf programs
func DetectCgroupFSMagic() (uint64, error) {
	// Run get cgroup mode again in case
	mode, err := DetectCgroupMode()
	if err != nil {
		return CGROUP_UNSET_VALUE, err
	}

	// Run this once and log output
	detectCgroupFSOnce.Do(func() {
		switch mode {
		case CGROUP_LEGACY, CGROUP_HYBRID:
			/* In both legacy or Hybrid modes we switch to Cgroupv1 from bpf side. */
			logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).Debug("Cgroup BPF helpers will run in raw Cgroup mode")
			cgroupFSMagic = unix.CGROUP_SUPER_MAGIC
		case CGROUP_UNIFIED:
			logger.GetLogger().WithField("cgroup.fs", cgroupFSPath).Debug("Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors")
			cgroupFSMagic = unix.CGROUP2_SUPER_MAGIC
		}
	})

	if cgroupFSMagic == CGROUP_UNSET_VALUE {
		return CGROUP_UNSET_VALUE, fmt.Errorf("could not detect Cgroup filesystem Magic")
	}

	return cgroupFSMagic, nil
}

// CgroupNameFromCstr() Returns a Golang string from the passed C language format string.
func CgroupNameFromCStr(cstr []byte) string {
	i := bytes.IndexByte(cstr, 0)
	if i == -1 {
		i = len(cstr)
	}
	return string(cstr[:i])
}
