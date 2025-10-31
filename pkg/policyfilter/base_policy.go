package policyfilter

import (
	"github.com/cilium/tetragon/pkg/labels"
)

type basePolicy struct {
	id                PolicyID
	namespace         string
	containerSelector labels.Selector
	podSelector       labels.Selector
}

func (b *basePolicy) setID(polID PolicyID) {
	b.id = polID
}

func (b *basePolicy) setFilters(namespace string, podSelector labels.Selector, containerSelector labels.Selector) {
	b.namespace = namespace
	b.podSelector = podSelector
	b.containerSelector = containerSelector
}

func (b *basePolicy) getID() PolicyID {
	return b.id
}

func (b *basePolicy) podInfoMatches(pod *podInfo) bool {
	if pod == nil {
		return false
	}
	return b.podMatches(pod.namespace, pod.labels)
}

func (b *basePolicy) podMatches(podNs string, podLabels labels.Labels) bool {
	if b.namespace != "" && podNs != b.namespace {
		return false
	}
	podLabels1 := make(labels.Labels)
	if podLabels != nil {
		podLabels1 = podLabels
	}
	if _, ok := podLabels1[labels.K8sPodNamespace]; !ok {
		podLabels1[labels.K8sPodNamespace] = podNs
	}
	return b.podSelector.Match(podLabels1)
}

func (b *basePolicy) containerMatches(container *containerInfo) bool {
	if container == nil {
		return false
	}
	filter := labels.Labels{
		"name": container.name,
		"repo": container.repo,
	}
	return b.containerSelector.Match(filter)
}

func (b *basePolicy) matchingContainersCgroupIDs(containers []containerInfo) []CgroupID {
	var ids []CgroupID
	for i := range containers {
		if b.containerMatches(&containers[i]) {
			ids = append(ids, containers[i].cgID)
		}
	}
	return ids
}
