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
			fn(&s[i])
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

// podContainerDiff compares the containers of two pods (old and new) and
// returns the container ids that were added and the container ids that were
// deleted.
func podContainerDiff(oldPod *v1.Pod, newPod *v1.Pod) ([]string, []string) {
	oldNr := len(oldPod.Status.ContainerStatuses)
	newNr := len(newPod.Status.ContainerStatuses)
	allIDs := make(map[string]struct{}, oldNr+newNr)

	oldIDs := make(map[string]struct{}, oldNr)
	podForAllContainers(oldPod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		if id == "" {
			return
		}
		oldIDs[id] = struct{}{}
		allIDs[id] = struct{}{}
	})

	newIDs := make(map[string]struct{}, newNr)
	podForAllContainers(newPod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		if id == "" {
			return
		}
		newIDs[id] = struct{}{}
		allIDs[id] = struct{}{}
	})

	addContIDs := []string{}
	delContIDs := []string{}
	for cID := range allIDs {
		if _, ok := oldIDs[cID]; !ok {
			// in the new, but not in the old
			addContIDs = append(addContIDs, cID)
		} else if _, ok := newIDs[cID]; !ok {
			// in the old, but not in the new
			delContIDs = append(delContIDs, cID)
		}
	}

	return addContIDs, delContIDs
}
