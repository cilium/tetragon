// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/watchermetrics"
	"github.com/cilium/tetragon/pkg/podhelpers"
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
	w watcher.PodAccessor,
	containerID string,
	binary string,
	args string,
	nspid uint32,
) *tetragon.Pod {
	if containerID == "" {
		return nil
	}
	pod, container, ok := w.FindContainer(containerID)
	if !ok {
		watchermetrics.GetWatcherErrors(watchermetrics.K8sWatcher, watchermetrics.FailedToGetPodError).Inc()
		logger.GetLogger().WithField("container id", containerID).Trace("failed to get pod")
		return nil
	}
	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}

	// This is the PID inside the container. Don't set it if zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
			Value: nspid,
		}
	}
	workloadObject, workloadType := podhelpers.GetWorkloadMetaFromPod(pod)
	watchermetrics.GetWatcherEvents(watchermetrics.K8sWatcher).Inc()
	return &tetragon.Pod{
		Namespace:    pod.Namespace,
		Workload:     workloadObject.Name,
		WorkloadKind: workloadType.Kind,
		Name:         pod.Name,
		PodLabels:    pod.Labels,
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
	}
}
