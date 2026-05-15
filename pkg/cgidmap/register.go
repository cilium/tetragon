// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"errors"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

// PodEventSource is the narrow capability cgidmap needs to keep its pod→
// container-cgroup mappings up to date. The concrete adapter lives in
// pkg/manager; tests can pass a hand-rolled fake satisfying the same
// interface.
type PodEventSource interface {
	OnPodAdd(handler func(pod *corev1.Pod))
	OnPodUpdate(handler func(oldPod, newPod *corev1.Pod))
	OnPodDelete(handler func(pod *corev1.Pod))
}

// Register wires cgidmap into the supplied pod event source. The caller is
// expected to gate this call on cgidmap being enabled, so a no-op
// registration when disabled does not appear in the startup log.
func Register(events PodEventSource) error {
	m, err := GlobalMap()
	if err != nil {
		// If cgidmap is disabled, this should not be called at all — the
		// caller is responsible for the gate. Surface the error so a
		// misconfiguration fails loudly instead of silently no-opping.
		if errors.Is(err, cgidDisabled) {
			return err
		}
		logger.GetLogger().Warn("failed to retrieve cgidmap, not registering pod handlers", logfields.Error, err)
		return err
	}

	events.OnPodAdd(func(pod *corev1.Pod) {
		updatePodHandler(m, pod)
	})
	events.OnPodUpdate(func(_ /* oldPod */, newPod *corev1.Pod) {
		updatePodHandler(m, newPod)
	})
	events.OnPodDelete(func(pod *corev1.Pod) {
		deletePodHandler(m, pod)
	})
	return nil
}

func deletePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().Warn("cgidmap, podDeleted: failed to parse pod id", "pod-id", pod.UID, logfields.Error, err)
		return
	}
	m.Update(podID, nil)
}

func updatePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().Warn("cgidmap, podUpdated: failed to parse pod id", "pod-id", pod.UID, logfields.Error, err)
		return
	}
	m.Update(podID, podhelpers.PodContainersIDs(pod))
}
