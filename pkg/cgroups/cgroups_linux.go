// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package cgroups

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

type deploymentEnv struct {
	id       DeploymentCode
	str      string
	endsWith string
}

type CgroupController struct {
	ID     uint32 // Hierarchy unique ID
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
		// If Tetragon is running as a systemd service, its
		// cgroup path will end with .service
		{id: DEPLOY_SD_SERVICE, endsWith: ".service"},
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
	cgrpHierarchy      uint32 // 0 in case of cgroupv2
	cgrpv1SubsystemIdx uint32 // Not set in case of cgroupv2
)

func (code CgroupModeCode) String() string {
	return [...]string{
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}[code]
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// CgroupFsMagicStr() Returns "Cgroupv2" or "Cgroupv1" based on passed magic.
func CgroupFsMagicStr(magic uint64) string {
	switch magic {
	case unix.CGROUP2_SUPER_MAGIC:
		return "Cgroupv2"
	case unix.CGROUP_SUPER_MAGIC:
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

type FileHandle struct {
	ID uint64
}

func GetCgroupIDFromPath(cgroupPath string) (uint64, error) {
	var fh FileHandle

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("nameToHandle on %s failed: %w", cgroupPath, err)
	}

	err = binary.Read(bytes.NewBuffer(handle.Bytes()), binary.LittleEndian, &fh)
	if err != nil {
		return 0, fmt.Errorf("decoding NameToHandleAt data failed: %w", err)
	}

	return fh.ID, nil
}

// parseCgroupv1SubSysIDs() parse cgroupv1 controllers and save their
// hierarchy IDs and related css indexes.
// If the 'memory' or 'cpuset' are not detected we fail, as we use them
// from BPF side to gather cgroup information and we need them to be
// exported by the kernel since their corresponding index allows us to
// fetch the cgroup from the corresponding cgroup subsystem state.
func parseCgroupv1SubSysIDs(filePath string) error {
	var allcontrollers []string

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	fscanner := bufio.NewScanner(file)
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
					return fmt.Errorf("Cgroupv1 default subsystem '%s' is indexed at idx=%d higher than CGROUP_SUBSYS_COUNT=%d",
						fields[0], idx, CGROUP_SUBSYS_COUNT)
				}

				id, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					CgroupControllers[i].ID = uint32(id)
					CgroupControllers[i].Idx = uint32(idx)
					CgroupControllers[i].Active = true
				} else {
					logger.GetLogger().Warn(fmt.Sprintf("Cgroupv1 parsing controller line from '%s' failed", filePath),
						logfields.Error, err,
						"cgroup.fs", cgroupFSPath,
						"cgroup.controller.name", controller.Name)
				}
			}
		}
		idx++
	}

	logger.GetLogger().Debug("Cgroupv1 available controllers",
		"cgroup.fs", cgroupFSPath,
		"cgroup.controllers", fmt.Sprintf("[%s]", strings.Join(allcontrollers, " ")))

	for _, controller := range CgroupControllers {
		// Print again everything that is available and if not, fail with error
		if controller.Active {
			logger.GetLogger().Info(fmt.Sprintf("Cgroupv1 supported controller '%s' is active on the system", controller.Name),
				"cgroup.fs", cgroupFSPath,
				"cgroup.controller.name", controller.Name,
				"cgroup.controller.hierarchyID", controller.ID,
				"cgroup.controller.index", controller.Idx)
		} else {
			var err error
			// Warn with error
			switch controller.Name {
			case "memory":
				err = errors.New("Cgroupv1 controller 'memory' is not active, ensure kernel CONFIG_MEMCG=y and CONFIG_MEMCG_V1=y are set")
			case "cpuset":
				err = errors.New("Cgroupv1 controller 'cpuset' is not active, ensure kernel CONFIG_CPUSETS=y and CONFIG_CPUSETS_V1=y are set")
			default:
				logger.GetLogger().Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name), "cgroup.fs", cgroupFSPath)
			}

			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name),
					logfields.Error, err, "cgroup.fs", cgroupFSPath)
				return err
			}
		}
	}

	return nil
}

// DiscoverSubSysIDs() Discover Cgroup SubSys IDs and indexes.
// of the corresponding controllers that we are interested
// in. We need this dynamic behavior since these controllers are
// compile config.
func DiscoverSubSysIDs() error {
	var err error
	magic := GetCgroupFSMagic()
	if magic == CGROUP_UNSET_VALUE {
		magic, err = DetectCgroupFSMagic()
		if err != nil {
			return err
		}
	}

	switch magic {
	case unix.CGROUP_SUPER_MAGIC:
		return parseCgroupv1SubSysIDs(filepath.Join(option.Config.ProcFS, "cgroups"))
	case unix.CGROUP2_SUPER_MAGIC:
		/* Parse Root Cgroup active controllers.
		 * This step helps debugging since we may have some
		 * race conditions when processes are moved or spawned in their
		 * appropriate cgroups which affect cgroup association, so
		 * having more information on the environment helps to debug
		 * or reproduce.
		 */
		path := filepath.Clean(fmt.Sprintf("%s/1/root/%s", option.Config.ProcFS, cgroupFSPath))
		return checkCgroupv2Controllers(path)
	}

	return errors.New("could not detect Cgroup filesystem")
}

func setDeploymentMode(cgroupPath string) error {
	if cgroupPath == "" {
		return errors.New("cgroup path is empty")
	}

	if deploymentMode != DEPLOY_UNKNOWN {
		return nil
	}

	if option.Config.EnableK8s {
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
		if d.str != "" && strings.Contains(cgroupPath, d.str) {
			deploymentMode = d.id
			return nil
		} else if d.endsWith != "" && strings.HasSuffix(cgroupPath, d.endsWith) {
			deploymentMode = d.id
			return nil
		}
	}

	/* Set deployment mode to unknown and do not fail */
	deploymentMode = DEPLOY_UNKNOWN
	return nil
}

func GetDeploymentMode() DeploymentCode {
	return deploymentMode
}

func GetCgroupMode() CgroupModeCode {
	return cgroupMode
}

func setCgrpHierarchyID(controller *CgroupController) {
	cgrpHierarchy = controller.ID
}

func setCgrp2HierarchyID() {
	cgrpHierarchy = CGROUP_DEFAULT_HIERARCHY
}

func setCgrpv1SubsystemIdx(controller *CgroupController) {
	cgrpv1SubsystemIdx = controller.Idx
}

// GetCgrpHierarchyID() returns the ID of the Cgroup hierarchy
// that is used to track processes. This is used mostly for
// Cgroupv1 as for Cgroupv2 we run in the default hierarchy.
func GetCgrpHierarchyID() uint32 {
	return cgrpHierarchy
}

// GetCgrpSubsystemIdx() returns the Index of the subsys
// or hierarchy to be used to track processes.
func GetCgrpv1SubsystemIdx() uint32 {
	return cgrpv1SubsystemIdx
}

// GetCgrpControllerName() returns the name of the controller that is
// being used as fallback from the css to get cgroup information and
// track processes.
func GetCgrpControllerName() string {
	for _, controller := range CgroupControllers {
		if controller.Active && controller.Idx == cgrpv1SubsystemIdx {
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
		if !controller.Active {
			logger.GetLogger().Debug(fmt.Sprintf("Cgroup controller '%s' is not active", controller.Name), "cgroup.fs", cgroupFSPath)
			continue
		}

		for _, s := range cgroupPaths {
			if strings.Contains(s, fmt.Sprintf(":%s:", controller.Name)) {
				idx := strings.Index(s, "/")
				path := s[idx+1:]
				cgroupPath := filepath.Join(cgroupFSPath, controller.Name, path)
				finalpath := filepath.Join(cgroupPath, "cgroup.procs")
				logger.GetLogger().Debug("Cgroupv1 probing environment and deployment detection",
					"cgroup.fs", cgroupFSPath,
					"cgroup.controller.name", controller.Name,
					"cgroup.path", cgroupPath)
				_, err := os.Stat(finalpath)
				if err != nil {
					// Probably running from root hierarchy or namespaced
					// run the detection again.
					logger.GetLogger().Debug("Cgroupv1 detected namespaces or running from root hierarchy, trying again",
						"cgroup.fs", cgroupFSPath,
						"cgroup.controller.name", controller.Name)
					err = setDeploymentMode(path)
					if err == nil {
						mode := GetDeploymentMode()
						if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
							// Cgroups are namespaced let's try again
							cgroupPath = filepath.Join(cgroupFSPath, controller.Name)
							finalpath = filepath.Join(cgroupPath, "cgroup.procs")
							_, err = os.Stat(finalpath)
						}
					}
				}

				if err != nil {
					logger.GetLogger().Warn(fmt.Sprintf("Failed to validate Cgroupv1 path '%s'", finalpath), "cgroup.fs", cgroupFSPath, logfields.Error, err)
					continue
				}

				// Run the deployment mode detection last again, fine to rerun.
				err = setDeploymentMode(path)
				if err != nil {
					logger.GetLogger().Warn("Failed to detect deployment mode from Cgroupv1 path", "cgroup.fs", cgroupFSPath, logfields.Error, err)
					continue
				}

				logger.GetLogger().Info(fmt.Sprintf("Cgroupv1 controller '%s' will be used", controller.Name),
					"cgroup.fs", cgroupFSPath,
					"cgroup.controller.name", controller.Name,
					"cgroup.controller.hierarchyID", controller.ID,
					"cgroup.controller.index", controller.Idx)

				setCgrpHierarchyID(&controller)
				setCgrpv1SubsystemIdx(&controller)
				logger.GetLogger().Info("Cgroupv1 hierarchy validated successfully",
					"cgroup.fs", cgroupFSPath,
					"cgroup.path", cgroupPath)
				return finalpath, nil
			}
		}
	}

	// Cgroupv1 hierarchy is not properly setup we can not support such systems,
	// reason should have been logged in above messages.
	return "", errors.New("could not validate Cgroupv1 hierarchies")
}

// Check and log Cgroupv2 active controllers
func checkCgroupv2Controllers(cgroupPath string) error {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return fmt.Errorf("no active controllers from '%s'", file)
	}

	logger.GetLogger().Info("Cgroupv2 supported controllers detected successfully",
		"cgroup.fs", cgroupFSPath,
		"cgroup.path", cgroupPath,
		"cgroup.controllers", strings.Fields(activeControllers),
		"cgroup.hierarchyID", CGROUP_DEFAULT_HIERARCHY)

	return nil
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
					mode := GetDeploymentMode()
					if mode == DEPLOY_K8S || mode == DEPLOY_CONTAINER {
						// Cgroups are namespaced let's try again
						cgroupPath = cgroupFSPath
						finalpath = filepath.Join(cgroupPath, "cgroup.procs")
						_, err = os.Stat(finalpath)
					}
				}
			}

			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Failed to validate Cgroupv2 path '%s'", finalpath), "cgroup.fs", cgroupFSPath, logfields.Error, err)
				break
			}

			// This should not be necessary but we have experienced some
			// container cgroup association errors in the past, and also
			// noticed some race conditions when a process is spawned into
			// a new cgroup, so to gather more information, let's try to
			// get the list of active cgroupv2 controllers in Tetragon
			// context, that should be same for all other k8s hierarchy.
			err = checkCgroupv2Controllers(cgroupPath)
			if err != nil {
				logger.GetLogger().Warn("Cgroupv2: failed to detect current active controllers", "cgroup.fs", cgroupFSPath, logfields.Error, err)
			}

			// Run the deployment mode detection last again, fine to rerun.
			err = setDeploymentMode(path)
			if err != nil {
				logger.GetLogger().Warn("Failed to detect deployment mode from Cgroupv2 path", "cgroup.fs", cgroupFSPath, logfields.Error, err)
				break
			}

			setCgrp2HierarchyID()
			logger.GetLogger().Info("Cgroupv2 hierarchy validated successfully",
				"cgroup.fs", cgroupFSPath,
				"cgroup.path", cgroupPath)
			return finalpath, nil
		}
	}

	// Cgroupv2 hierarchy is not properly setup we can not support such systems,
	// reason should have been logged in above messages.
	return "", errors.New("could not validate Cgroupv2 hierarchy")
}

func getPIDCgroupPaths(pid uint32) ([]string, error) {
	file := filepath.Join(option.Config.ProcFS, strconv.FormatUint(uint64(pid), 10), "cgroup")

	cgroups, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", file, err)
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

	cgroupPaths, err := getPIDCgroupPaths(pid)
	if err != nil {
		logger.GetLogger().Warn(fmt.Sprintf("Unable to get Cgroup paths for pid=%d", pid), "cgroup.fs", cgroupFSPath, logfields.Error, err)
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
			err = errors.New("could not detect Cgroup Mode")
		}

		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("Unable to find Cgroup migration path for pid=%d", pid), "cgroup.fs", cgroupFSPath, logfields.Error, err)
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

	switch st.Type {
	case unix.CGROUP2_SUPER_MAGIC:
		return CGROUP_UNIFIED, nil
	case unix.TMPFS_MAGIC:
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
			logger.GetLogger().Debug("Could not detect Cgroup Mode", "cgroup.fs", cgroupFSPath, logfields.Error, err)
			cgroupMode, err = detectCgroupMode(defaults.Cgroup2Dir)
			if err != nil {
				logger.GetLogger().Debug("Could not detect Cgroup Mode", "cgroup.fs", defaults.Cgroup2Dir, logfields.Error, err)
			} else {
				cgroupFSPath = defaults.Cgroup2Dir
			}
		}
		if cgroupMode != CGROUP_UNDEF {
			logger.GetLogger().Info("Cgroup mode detection succeeded",
				"cgroup.fs", cgroupFSPath,
				"cgroup.mode", cgroupMode.String())
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return CGROUP_UNDEF, errors.New("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

func detectDeploymentMode() (DeploymentCode, error) {
	mode := GetDeploymentMode()
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

	return GetDeploymentMode(), nil
}

func DetectDeploymentMode() (DeploymentCode, error) {
	detectDeploymentOnce.Do(func() {
		_, err := detectDeploymentMode()
		if err != nil {
			logger.GetLogger().Warn("Detection of deployment mode failed", "cgroup.fs", cgroupFSPath, logfields.Error, err)
			return
		}
	})

	mode := GetDeploymentMode()
	if mode == DEPLOY_UNKNOWN {
		logger.GetLogger().Warn("Deployment mode detection failed",
			"cgroup.fs", cgroupFSPath,
			"deployment.mode", DeploymentCode(mode).String())
	} else {
		logger.GetLogger().Info("Deployment mode detection succeeded",
			"cgroup.fs", cgroupFSPath,
			"deployment.mode", DeploymentCode(mode).String())
	}

	return mode, nil
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
			logger.GetLogger().Debug("Cgroup BPF helpers will run in raw Cgroup mode", "cgroup.fs", cgroupFSPath)
			cgroupFSMagic = unix.CGROUP_SUPER_MAGIC
		case CGROUP_UNIFIED:
			logger.GetLogger().Debug("Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors", "cgroup.fs", cgroupFSPath)
			cgroupFSMagic = unix.CGROUP2_SUPER_MAGIC
		}
	})

	if cgroupFSMagic == CGROUP_UNSET_VALUE {
		return CGROUP_UNSET_VALUE, errors.New("could not detect Cgroup filesystem Magic")
	}

	return cgroupFSMagic, nil
}

func tryHostCgroup(path string) error {
	var st, pst unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("cannot determine cgroup root: error acessing path '%s': %w", path, err)
	}

	parent := filepath.Dir(path)
	if err := unix.Lstat(parent, &pst); err != nil {
		return fmt.Errorf("cannot determine cgroup root: error acessing parent path '%s': %w", parent, err)
	}

	if st.Dev == pst.Dev {
		return fmt.Errorf("cannot determine cgroup root: '%s' does not appear to be a mount point", path)
	}

	fst := unix.Statfs_t{}
	if err := unix.Statfs(path, &fst); err != nil {
		return fmt.Errorf("cannot determine cgroup root: failed to get info for '%s'", path)
	}

	switch fst.Type {
	case unix.CGROUP2_SUPER_MAGIC, unix.CGROUP_SUPER_MAGIC:
		return nil
	default:
		return fmt.Errorf("cannot determine cgroup root: path '%s' is not a cgroup fs", path)
	}
}

// HostCgroupRoot tries to retrieve the host cgroup root
//
// For cgroupv1, we return the directory of the contoller currently used.
//
// NB(kkourt): for now we are checking /sys/fs/cgroup under host /proc's init.
// For systems where the cgroup is mounted in a non-standard location, we could
// also check host's /proc/mounts.
func HostCgroupRoot() (string, error) {
	components := []string{
		option.Config.ProcFS, "1", "root",
		"sys", "fs", "cgroup",
		GetCgrpControllerName(),
	}

	path1 := filepath.Join(components...)
	err1 := tryHostCgroup(path1)
	if err1 == nil {
		return path1, nil
	}

	path2 := filepath.Join(components[:len(components)-1]...)
	err2 := tryHostCgroup(path2)
	if err2 == nil {
		return path2, nil
	}

	err := multierr.Append(
		fmt.Errorf("failed to set path %s as cgroup root %w", path1, err1),
		fmt.Errorf("failed to set path %s as cgroup root %w", path2, err2),
	)
	return "", fmt.Errorf("failed to set cgroup root: %w", err)
}

// CgroupIDFromPID returns the cgroup id for a given pid.
func CgroupIDFromPID(pid uint32) (uint64, error) {
	cgroupFile := fmt.Sprintf("%s/%d/cgroup", option.Config.ProcFS, pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return 0, err
	}

	pathPrefix := option.Config.ProcFS + "/1/root/sys/fs/cgroup"

	// pathFunc returns (true, path) if it found the proper cgroup path, or (false, "") if it
	// did not. There are two versions of this function, one for cgroup v1 and one for cgroup
	// v2.
	var pathFunc func(line string) (bool, string)

	switch GetCgroupMode() {
	case CGROUP_UNDEF:
		return 0, errors.New("cgroup mode undefined")
	case CGROUP_UNIFIED:
		pathFunc = func(line string) (bool, string) {
			v2Prefix := "0::"
			if !strings.HasPrefix(line, v2Prefix) {
				return false, ""
			}
			return true, fmt.Sprintf("%s/%s", pathPrefix, line[len(v2Prefix):])
		}
	case CGROUP_LEGACY, CGROUP_HYBRID:
		pathFunc = func(line string) (bool, string) {
			// TODO: test the cgroup v1 implementation
			v1Prefix := fmt.Sprintf("%d:%s:", GetCgrpHierarchyID(), GetCgrpControllerName())
			if !strings.HasPrefix(line, v1Prefix) {
				return false, ""
			}
			return true, fmt.Sprintf("%s/%s/%s", pathPrefix, GetCgrpControllerName(), line[len(v1Prefix):])
		}
	}

	lines := strings.Split(string(data), "\n")
	var path string
	for _, line := range lines {
		var ok bool
		if ok, path = pathFunc(line); ok {
			break
		}
	}

	if len(path) == 0 {
		return 0, errors.New("failed to find proper cgroup")
	}

	cgID, err := GetCgroupIDFromPath(path)
	if err != nil {
		return 0, err
	}

	return cgID, nil
}

// GetCgroupIDFromSubCgroup deals with some idiosyncrancies of container runtimes
//
// Typically, the container processes run in the cgroup path specified in the OCI spec under
// cgroupsPath. crun, however, is an exception because it uses another directory (called subgroup)
// under the cgroupsPath:
// https://github.com/containers/crun/blob/main/crun.1.md#runocisystemdsubgroupsubgroup.
//
// This function deals with this by checking for a child directory. If it finds one (and only one)
// it uses the cgroup id from the child.
func GetCgroupIDFromSubCgroup(p string) (uint64, error) {

	getSingleDirChild := func() string {
		var ret string
		dentries, err := os.ReadDir(p)
		if err != nil {
			return ""
		}
		for _, dentry := range dentries {
			if !dentry.IsDir() {
				continue
			}

			if ret == "" {
				ret = dentry.Name()
			} else {
				// NB: there are more than one directories :( nothing reasonable we
				// can do at this point bail out
				return ""
			}
		}

		return ret
	}

	child := getSingleDirChild()
	if child != "" {
		p = filepath.Join(p, child)
	}

	return GetCgroupIDFromPath(p)
}
