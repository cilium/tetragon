// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package podhelpers

import (
	"strings"

	v1 "k8s.io/api/core/v1"
)

// podForAllContainers runs the given functions for all containers in a pod
func podForAllContainers(pod *v1.Pod, fn func(c *v1.ContainerStatus)) {
	run := func(s []v1.ContainerStatus) {
		for i := range s {
			if s[i].State.Running != nil {
				fn(&s[i])
			}
		}
	}

	run(pod.Status.InitContainerStatuses)
	run(pod.Status.ContainerStatuses)
	run(pod.Status.EphemeralContainerStatuses)
}

func containerIDFromContainerStatus(c *v1.ContainerStatus) string {
	ret := c.ContainerID
	if idx := strings.Index(ret, "://"); idx != -1 {
		ret = ret[idx+3:]
	}
	return ret
}

func PodContainersIDs(pod *v1.Pod) []string {
	ret := make([]string, 0)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		ret = append(ret, id)
	})
	return ret
}

type ContainerInfo struct {
	Name string
	Repo string
}

func PodContainersInfo(pod *v1.Pod) []ContainerInfo {
	ret := make([]ContainerInfo, 0)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		var repo string
		if parts := strings.Split(c.ImageID, "@"); len(parts) == 2 { // example ImageID: docker.io/library/ubuntu@sha256:aadf9a3f5eda81295050d13dabe851b26a67597e424a908f25a63f589dfed48f
			repo = parts[0]
		}
		ret = append(ret, ContainerInfo{Name: c.Name, Repo: repo})
	})
	return ret
}
