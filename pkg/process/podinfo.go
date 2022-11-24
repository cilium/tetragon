// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	hubblev1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/watcher"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
)

func getExecCommand(probe *corev1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func getProbes(pod *corev1.Pod, containerStatus *corev1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}

func getPodInfo(
	w watcher.K8sResourceWatcher,
	containerID string,
	binary string,
	args string,
	nspid uint32,
) (*tetragon.Pod, *hubblev1.Endpoint) {
	if containerID == "" {
		return nil, nil
	}
	pod, container, ok := w.FindPod(containerID)
	if !ok {
		watchermetrics.GetWatcherErrors("k8s", watchermetrics.FailedToGetPodError).Inc()
		logger.GetLogger().WithField("container id", containerID).Trace("failed to get pod")
		return nil, nil
	}
	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}

	ciliumState := cilium.GetCiliumState()
	endpoint, ok := ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	var labels []string
	if ok {
		labels = endpoint.Labels
	}

	// Don't set container PIDs if it's zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
			Value: nspid,
		}
	}

	watchermetrics.GetWatcherEvents("k8s").Inc()
	return &tetragon.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Labels:    labels,
		PodLabels: pod.Labels,
		Container: &tetragon.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &tetragon.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime:      startTime,
			MaybeExecProbe: maybeExecProbe,
		},
	}, endpoint
}
