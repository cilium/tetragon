// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package k8sjob

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestNewJob(t *testing.T) {
	job, err := NewJob(Opts{
		Namespace: "ns",
		Image:     "img:tag",
		Node:      "node-1",
		Args:      []string{"kprobe-lseek", "--monitor-mode"},
		Timeout:   time.Minute,
	})
	require.NoError(t, err)

	require.Equal(t, "ns", job.Namespace)
	spec := job.Spec.Template.Spec
	require.Equal(t, "node-1", spec.NodeName)
	require.Equal(t, "img:tag", spec.InitContainers[0].Image)
	require.Equal(t, "img:tag", spec.Containers[0].Image)
	require.Equal(t, []string{"kprobe-lseek", "--monitor-mode"}, spec.Containers[0].Args[len(spec.Containers[0].Args)-2:])
	require.Equal(t, int64((startTimeout + time.Minute).Seconds()), *job.Spec.ActiveDeadlineSeconds)
}

func TestNewJobNoArgs(t *testing.T) {
	_, err := NewJob(Opts{Namespace: "ns", Image: "img"})
	require.ErrorIs(t, err, errNoTestArgs)
}

func TestPodStarted(t *testing.T) {
	status := func(name string, state corev1.ContainerState) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, State: state}
	}
	waiting := func(reason string) corev1.ContainerState {
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}
	}
	exited := func(code int32) corev1.ContainerState {
		return corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code}}
	}
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}

	tests := []struct {
		name    string
		phase   corev1.PodPhase
		init    []corev1.ContainerStatus
		main    []corev1.ContainerStatus
		started bool
		failed  bool
	}{
		{name: "pending"},
		{name: "init running", init: []corev1.ContainerStatus{status("stage-tester-progs", running)}},
		{name: "init failed", init: []corev1.ContainerStatus{status("stage-tester-progs", exited(1))}, failed: true},
		{name: "image missing", init: []corev1.ContainerStatus{status("stage-tester-progs", waiting("ErrImageNeverPull"))}, failed: true},
		{name: "creating", init: []corev1.ContainerStatus{status("stage-tester-progs", exited(0))}, main: []corev1.ContainerStatus{status(container, waiting("ContainerCreating"))}},
		{name: "evicted", phase: corev1.PodFailed, failed: true},
		{name: "running", main: []corev1.ContainerStatus{status(container, running)}, started: true},
		{name: "tests failed", main: []corev1.ContainerStatus{status(container, exited(1))}, started: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Status: corev1.PodStatus{Phase: tc.phase, InitContainerStatuses: tc.init, ContainerStatuses: tc.main}}
			started, err := podStarted(pod)
			require.Equal(t, tc.started, started)
			if tc.failed {
				require.ErrorIs(t, err, errPodFailed)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
