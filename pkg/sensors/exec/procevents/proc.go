// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/cilium/tetragon/pkg/api/processapi"
)

const (
	// ContainerIDLength is the standard length of the Container ID
	ContainerIdLength = 64

	// BpfContainerIdLength Minimum 31 chars to assume it is a Container ID
	// in case it was truncated
	BpfContainerIdLength = 31
)

// ProcsContainerIdOffset Returns the container ID and its offset
// This can fail, better use LookupContainerId to handle different container runtimes.
func ProcsContainerIdOffset(subdir string) (string, int) {
	// If the cgroup subdir contains ":" it means that we are dealing with
	// Linux.CgroupPath where the cgroup driver is cgroupfs
	// https://github.com/opencontainers/runc/blob/main/docs/systemd.md
	// In this case let's split the name and take the last one
	p := strings.LastIndex(subdir, ":") + 1
	fields := strings.Split(subdir, ":")
	idStr := fields[len(fields)-1]

	off := strings.LastIndex(idStr, "-") + 1
	s := strings.Split(idStr, "-")

	return s[len(s)-1], off + p
}

// LookupContainerId returns the container ID as a 31 character string length from the full cgroup path
// cgroup argument is the full cgroup path
// bpfSource is set to true if cgroup was obtained from BPF, otherwise false.
// walkParent if set then walk the parent hierarchy subdirs and try to find the container ID of the process,
//
//	this will allow to return the container id of services running inside, example: init.service etc.
//
// Returns the container ID as a string of 31 characters and its offset on the full cgroup path,
// otherwise on errors an empty string and 0 as offset.
func LookupContainerId(cgroup string, bpfSource bool, walkParent bool) (string, int) {
	idTruncated := false
	subDirs := strings.Split(cgroup, "/")
	subdir := subDirs[len(subDirs)-1]

	// Special case for syscont-cgroup-root installed by
	// sysbox nested containers. In this case set with
	// outermost container.
	if strings.Contains(subdir, "syscont-cgroup-root") {
		if len(subDirs) > 4 {
			subdir = subDirs[4]
			walkParent = false
		}
	}

	// Check if the cgroup was obtained from BPF and if the last subdir
	// cgroup length equals DOCKER_ID_LENGTH -1, then:
	// It was probably truncated to DOCKER_ID_LENGTH, let's be flexible
	// try to match containerID without asserting the
	// ContainerIDLength == 64 due to the truncation as it will be less anyway.
	// We trust BPF part that it will always return null terminated
	// DOCKER_ID_LENGTH. For other cases where we read through /proc/
	// strings are not truncated.
	if bpfSource && len(subdir) >= processapi.DOCKER_ID_LENGTH-1 {
		idTruncated = true
	}

	container, i := ProcsContainerIdOffset(subdir)

	// Let's first check if this was a valid container id, it can be only the id
	// or the id.scope
	// systemd units at the end of a cgroup path can only be a type .scope or .service
	// However if it is a service then it means some service inside the container, if
	// we are interested into it then we should walk the parent subdir with
	// walkParent argument set and get its parent cgroup
	if !strings.HasSuffix(container, "service") &&
		((len(container) >= ContainerIdLength) ||
			(idTruncated && len(container) >= BpfContainerIdLength)) {
		// Return first 31 chars. If the string is less than 31 chars
		// it's not a docker ID so skip it. For example docker.server
		// will get here.
		return container[:BpfContainerIdLength], i
	}

	// Podman may set the last subdir to 'container' so let's walk parent subdir
	if strings.Contains(cgroup, "libpod") && container == "container" {
		walkParent = true
	}

	// Should we walk the parent subdirs
	if !walkParent {
		return "", 0
	}

	// Walk the parent subdirs until the first ancestor which is not included
	for j := len(subDirs) - 2; j > 1; j-- {
		container, i = ProcsContainerIdOffset(subDirs[j])
		// Either container ID or the first transient scope unit
		if len(container) == ContainerIdLength || (len(container) > ContainerIdLength && strings.HasSuffix(container, "scope")) {
			// Return first 31 chars. If the string is less than 31 chars
			// it's not a docker ID so skip it. For example docker.server
			// will get here.
			return container[:BpfContainerIdLength], i
		}
	}

	return "", 0
}

func procsFilename(args []byte) (string, string) {
	cmdArgs := bytes.Split(args, []byte{0x00})
	filename := string(cmdArgs[0])
	cmds := string(bytes.Join(cmdArgs[1:], []byte{0x00}))
	return cmds, filename
}

func procsFindDockerId(cgroups string) (string, int) {
	cgrpPaths := strings.Split(cgroups, "\n")
	for _, s := range cgrpPaths {
		if strings.Contains(s, "pods") || strings.Contains(s, "docker") ||
			strings.Contains(s, "libpod") {
			// Get the container ID and the offset
			container, i := LookupContainerId(s, false, false)
			if container != "" {
				return container, i
			}
		}
		// In some environments, such as the GitHub Ubuntu CI runner, docker cgroups do not contain the docker keyword but do end with a hex ID in their last component. Fall back to a naive approach here to handle that case.
		components := strings.Split(s, "/")
		if len(components) > 0 {
			id := components[len(components)-1]
			_, err := hex.DecodeString(id)
			if err == nil {
				if len(id) >= 31 {
					return id[:31], len(strings.Join(components[:len(components)-1], "")) + 1
				}
			}
		}
	}
	return "", 0
}
