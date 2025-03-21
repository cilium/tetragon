// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package cgroups

import (
	"errors"
)

func CgroupFsMagicStr(magic uint64) string {
	return ""
}

func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	return 0, errors.New("not Supported on windows")
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
	return CGROUP_UNDEF, errors.New("not Supported on windows")
}

func DetectDeploymentMode() (DeploymentCode, error) {
	return DEPLOY_UNKNOWN, errors.New("not Supported on windows")
}

func DetectCgroupFSMagic() (uint64, error) {
	return CGROUP_UNSET_VALUE, errors.New("not Supported on windows")
}

func HostCgroupRoot() (string, error) {
	return "", errors.New("not Supported on windows")
}

func CgroupIDFromPID(pid uint32) (uint64, error) {
	return 0, errors.New("not Supported on windows")
}

func GetCgroupIDFromSubCgroup(p string) (uint64, error) {

	return 0, errors.New("not Supported on windows")
}
