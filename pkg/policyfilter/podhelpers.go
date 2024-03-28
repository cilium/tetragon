// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

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

func podContainersIDs(pod *v1.Pod) []string {
	ret := make([]string, 0)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		ret = append(ret, id)
	})
	return ret
}

func podContainersNames(pod *v1.Pod) []string {
	ret := make([]string, 0)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		ret = append(ret, c.Name)
	})
	return ret
}
