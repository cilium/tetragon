package cgroups

import "bytes"

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
	id       DeploymentCode
	str      string
	endsWith string
}

const (
	// Deployment modes
	DEPLOY_UNKNOWN    DeploymentCode = iota
	DEPLOY_K8S        DeploymentCode = 1  // K8s deployment
	DEPLOY_CONTAINER  DeploymentCode = 2  // Container docker, podman, etc
	DEPLOY_SD_SERVICE DeploymentCode = 10 // Systemd service
	DEPLOY_SD_USER    DeploymentCode = 11 // Systemd user session
)

func (op DeploymentCode) String() string {
	return [...]string{
		DEPLOY_UNKNOWN:    "unknown",
		DEPLOY_K8S:        "Kubernetes",
		DEPLOY_CONTAINER:  "Container",
		DEPLOY_SD_SERVICE: "systemd service",
		DEPLOY_SD_USER:    "systemd user session",
	}[op]
}

// CgroupNameFromCstr() Returns a Golang string from the passed C language format string.
func CgroupNameFromCStr(cstr []byte) string {
	i := bytes.IndexByte(cstr, 0)
	if i == -1 {
		i = len(cstr)
	}
	return string(cstr[:i])
}
