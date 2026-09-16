// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package cgidmap

import (
	"context"
	"fmt"
	"uuid"

	corev1 "k8s.io/api/core/v1"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/podhelpers"
)

// Register wires cgidmap into the supplied pod event source. The caller is
// expected to gate this call on cgidmap being enabled, so a no-op
// registration when disabled does not appear in the startup log.
func Register(src events.PodEventSource) error {
	m, err := GlobalMap()
	if err != nil {
		return fmt.Errorf("failed to retrieve cgidmap, not registering pod handlers: %w", err)
	}

	if err := src.OnPodAdd(func(pod *corev1.Pod) {
		updatePodHandler(m, pod)
	}); err != nil {
		return err
	}
	if err := src.OnPodUpdate(func(_ /* oldPod */, newPod *corev1.Pod) {
		updatePodHandler(m, newPod)
	}); err != nil {
		return err
	}
	return src.OnPodDelete(func(pod *corev1.Pod) {
		deletePodHandler(m, pod)
	})
}

func deletePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().Warn("cgidmap, podDeleted: failed to parse pod id", "pod-id", pod.UID, logfields.Error, err)
		return
	}
	m.Update(podID, nil)
	m.UpdatePodSandbox(podID, "")
}

func updatePodHandler(m Map, pod *corev1.Pod) {
	podID, err := uuid.Parse(string(pod.UID))
	if err != nil {
		logger.GetLogger().Warn("cgidmap, podUpdated: failed to parse pod id", "pod-id", pod.UID, logfields.Error, err)
		return
	}
	m.Update(podID, podhelpers.PodContainersIDs(pod))

	var sandboxID string
	ctx := context.Background()
	if cli, err := cri.GetClient(ctx); err == nil {
		req := criapi.ListPodSandboxRequest{
			Filter: &criapi.PodSandboxFilter{
				LabelSelector: map[string]string{
					"io.kubernetes.pod.uid": string(pod.UID),
				},
			},
		}
		if res, err := cli.ListPodSandbox(ctx, &req); err != nil {
			logger.GetLogger().Warn("cgidmap, podUpdated: failed to list pod sandbox", "pod-id", pod.UID, logfields.Error, err)
		} else {
			for _, item := range res.GetItems() {
				if id := item.GetId(); id != "" {
					sandboxID = id
					break
				}
			}
		}
	}

	m.UpdatePodSandbox(podID, sandboxID)
}
