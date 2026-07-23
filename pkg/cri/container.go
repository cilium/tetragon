// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package cri

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
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

// containerInfoJSON returns the verbose ContainerStatus info JSON for a
// container, the payload ContainerPID and CgroupPath extract fields from.
func containerInfoJSON(ctx context.Context, cli criapi.RuntimeServiceClient, containerID string) (string, error) {
	req := criapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}
	res, err := cli.ContainerStatus(ctx, &req)
	if err != nil {
		return "", err
	}

	json, ok := res.GetInfo()["info"]
	if !ok {
		return "", errors.New("could not find info")
	}
	return json, nil
}

// ContainerPID returns the host-namespace PID of the container's main process,
// from the runtime's verbose ContainerStatus info. It is authoritative (keyed
// by container id), unlike picking a process from the process cache.
func ContainerPID(ctx context.Context, cli criapi.RuntimeServiceClient, containerID string) (uint32, error) {
	json, err := containerInfoJSON(ctx, cli, containerID)
	if err != nil {
		return 0, fmt.Errorf("CRI ContainerStatus for %s: %w", containerID, err)
	}

	pid := gjson.Get(json, "pid").Int()
	if pid <= 0 {
		return 0, errors.New("failed to find pid in container info")
	}
	return uint32(pid), nil
}

// RunningContainer identifies a running container and its pod (the attach
// key). It deliberately carries no sandbox namespace/labels: those may be
// stale, so pod-selector matching must use the informer's current data.
type RunningContainer struct {
	ID     string // CRI container id (bare, matches the stripped k8s container id)
	PodUID string
}

// RunningContainers lists the running containers known to the CRI runtime,
// joined with their ready pod sandboxes: the sandbox supplies the pod UID for
// the attach key, which ListContainers does not.
func RunningContainers(ctx context.Context, cli criapi.RuntimeServiceClient) ([]RunningContainer, error) {
	sbResp, err := cli.ListPodSandbox(ctx, &criapi.ListPodSandboxRequest{
		Filter: &criapi.PodSandboxFilter{
			State: &criapi.PodSandboxStateValue{State: criapi.PodSandboxState_SANDBOX_READY},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CRI ListPodSandbox failed: %w", err)
	}
	sandboxes := make(map[string]*criapi.PodSandbox, len(sbResp.GetItems()))
	for _, sb := range sbResp.GetItems() {
		sandboxes[sb.GetId()] = sb
	}

	cResp, err := cli.ListContainers(ctx, &criapi.ListContainersRequest{
		Filter: &criapi.ContainerFilter{
			State: &criapi.ContainerStateValue{State: criapi.ContainerState_CONTAINER_RUNNING},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CRI ListContainers failed: %w", err)
	}

	out := make([]RunningContainer, 0, len(cResp.GetContainers()))
	for _, c := range cResp.GetContainers() {
		sb := sandboxes[c.GetPodSandboxId()]
		if sb == nil {
			// container without a known sandbox: cannot recover pod metadata to
			// match a selector, so skip it.
			continue
		}
		md := sb.GetMetadata()
		if c.GetId() == "" || md.GetUid() == "" {
			// Without both ids the attach key (podUID/containerID) would be
			// malformed and could never be detached on pod delete; skip.
			continue
		}
		out = append(out, RunningContainer{
			ID:     c.GetId(),
			PodUID: md.GetUid(),
		})
	}
	return out, nil
}

func CgroupPath(ctx context.Context, cli criapi.RuntimeServiceClient, containerID string) (string, error) {
	json, err := containerInfoJSON(ctx, cli, containerID)
	if err != nil {
		return "", err
	}

	ret := gjson.Get(json, "runtimeSpec.linux.cgroupsPath").String()
	if ret == "" {
		return "", errors.New("failed to find cgroupsPath in json")
	}

	return ParseCgroupsPath(ret)
}
