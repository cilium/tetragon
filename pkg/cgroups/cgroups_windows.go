// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package cgroups

import (
	"errors"

	"github.com/cilium/tetragon/pkg/constants"
)

func CgroupFsMagicStr(magic uint64) string {
	return ""
}

func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	return 0, constants.ErrWindowsNotSupported
}

func DiscoverSubSysIds() error {
	return errors.New("could not detect cgroup filesystem on windows")
}

func GetDeploymentMode() DeploymentCode {
	return DEPLOY_UNKNOWN
}

func GetCgroupMode() CgroupModeCode {
	return CGROUP_UNDEF
}

func GetCgrpHierarchyID() uint32 {
	return 0
}

func GetCgrpv1SubsystemIdx() uint32 {
	return 0
}

func GetCgrpControllerName() string {
	return ""
}

func DetectCgroupMode() (CgroupModeCode, error) {
	return CGROUP_UNDEF, constants.ErrWindowsNotSupported
}

func DetectDeploymentMode() (DeploymentCode, error) {
	return DEPLOY_UNKNOWN, constants.ErrWindowsNotSupported
}

func DetectCgroupFSMagic() (uint64, error) {
	return CGROUP_UNSET_VALUE, constants.ErrWindowsNotSupported
}

func HostCgroupRoot() (string, error) {
	return "", constants.ErrWindowsNotSupported
}

func CgroupIDFromPID(pid uint32) (uint64, error) {
	return 0, constants.ErrWindowsNotSupported
}

func GetCgroupIDFromSubCgroup(p string) (uint64, error) {

	return 0, constants.ErrWindowsNotSupported
}
