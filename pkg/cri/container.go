// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package cri

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// NB(kkourt): taken from github.com/opencontainers/runc/libcontainer/cgroups/systemd
// which does not work due to a ebpf incomaptibility:
// # github.com/opencontainers/runc/libcontainer/cgroups/ebpf
// vendor/github.com/opencontainers/runc/libcontainer/cgroups/ebpf/ebpf_linux.go:190:3: unknown field Replace in struct literal of type link.RawAttachProgramOptions
//
// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func systemdExpandSlice(slice string) (string, error) {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if len(slice) < len(suffix) || !strings.HasSuffix(slice, suffix) {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	var path, prefix string
	sliceName := strings.TrimSuffix(slice, suffix)
	// if input was -.slice, we should just return root now
	if sliceName == "-" {
		return "/", nil
	}
	for component := range strings.SplitSeq(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return "", fmt.Errorf("invalid slice name: %s", slice)
		}

		// Append the component to the path and to the prefix.
		path += "/" + prefix + component + suffix
		prefix += component + "-"
	}
	return path, nil
}

func ParseCgroupsPath(cgroupPath string) (string, error) {
	if strings.Contains(cgroupPath, "/") {
		return cgroupPath, nil
	}

	// There are some cases where CgroupsPath  is specified as "slice:prefix:name"
	// From runc --help
	//   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name"
	//                       for e.g. "system.slice:runc:434234"
	//
	// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/specconv/spec_linux.go#L655-L663
	parts := strings.Split(cgroupPath, ":")
	if len(parts) == 3 {
		var err error
		slice, scope, name := parts[0], parts[1], parts[2]
		slice, err = systemdExpandSlice(slice)
		if err != nil {
			return "", fmt.Errorf("failed to parse cgroup path: %s (%s does not seem to be a slice)", cgroupPath, slice)
		}
		// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/cgroups/systemd/common.go#L95-L101
		if !strings.HasSuffix(name, ".slice") {
			name = scope + "-" + name + ".scope"
		}
		return filepath.Join(slice, name), nil
	}

	return "", fmt.Errorf("unknown cgroup path: %s", cgroupPath)
}

func CgroupPath(ctx context.Context, cli criapi.RuntimeServiceClient, containerID string) (string, error) {
	var info map[string]string

	req := criapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}
	res, err := cli.ContainerStatus(ctx, &req)
	if err == nil {
		info = res.GetInfo()
	} else {
		sbReq := criapi.PodSandboxStatusRequest{
			PodSandboxId: containerID,
			Verbose:      true,
		}
		sbRes, sbErr := cli.PodSandboxStatus(ctx, &sbReq)
		if sbErr != nil {
			return "", errors.Join(err, sbErr)
		}
		info = sbRes.GetInfo()
	}

	if info == nil {
		return "", errors.New("no container or pod sandbox info")
	}

	infoJSON, ok := info["info"]
	if !ok {
		return "", errors.New("could not find info")
	}

	var spec struct {
		RuntimeSpec struct {
			Linux struct {
				CgroupsPath string `json:"cgroupsPath"`
			} `json:"linux"`
		} `json:"runtimeSpec"`
	}
	if err := json.Unmarshal([]byte(infoJSON), &spec); err != nil {
		return "", fmt.Errorf("failed to parse info: %w", err)
	}

	ret := spec.RuntimeSpec.Linux.CgroupsPath
	if ret == "" {
		return "", errors.New("failed to find cgroupsPath in json")
	}

	return ParseCgroupsPath(ret)
}

// ContainerPid returns the PID of the container's init process, as numbered
// in the runtime's PID namespace.
func ContainerPid(ctx context.Context, cli criapi.RuntimeServiceClient, containerID string) (uint32, error) {
	res, err := cli.ContainerStatus(ctx, &criapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
	if err != nil {
		return 0, err
	}

	infoJSON, ok := res.GetInfo()["info"]
	if !ok {
		return 0, errors.New("could not find info")
	}

	var info struct {
		Pid uint32 `json:"pid"`
	}
	if err := json.Unmarshal([]byte(infoJSON), &info); err != nil {
		return 0, fmt.Errorf("failed to parse info: %w", err)
	}
	if info.Pid == 0 {
		return 0, errors.New("container has no running process")
	}
	return info.Pid, nil
}
