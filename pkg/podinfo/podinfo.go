// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package podinfo

import (
	"net"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/cilium"

	coreV1 "k8s.io/api/core/v1"
)

func getExecCommand(probe *coreV1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func GetPodInfoOfIp(ip net.IP) *fgs.Pod {
	ciliumState := cilium.GetCiliumState()
	ipcacheEntry, ok := ciliumState.GetIPCache().GetIPIdentity(ip)
	if !ok {
		return nil
	}
	return &fgs.Pod{
		Namespace: ipcacheEntry.Namespace,
		Name:      ipcacheEntry.PodName,
		Labels:    nil,
		Container: nil,
	}
}

func GetProbes(pod *coreV1.Pod, containerStatus *coreV1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}
