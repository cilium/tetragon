// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package policytest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestNewK8sJob(t *testing.T) {
	job, err := newK8sJob(&K8sConf{
		Namespace: "ns",
		Image:     "img:tag",
		Node:      "node-1",
		ExtraArgs: []string{"--ee-bindir=/ee"},
		Timeout:   time.Minute,
	}, []string{"--monitor-mode", "--", "kprobe-lseek"})
	require.NoError(t, err)

	require.Equal(t, "ns", job.Namespace)
	spec := job.Spec.Template.Spec
	require.Equal(t, "node-1", spec.NodeName)
	require.Equal(t, "img:tag", spec.InitContainers[0].Image)
	require.Equal(t, "img:tag", spec.Containers[0].Image)
	args := spec.Containers[0].Args
	require.Contains(t, args, "--output=json")
	require.Equal(t, []string{"--ee-bindir=/ee", "--monitor-mode", "--", "kprobe-lseek"}, args[len(args)-4:])
	require.Equal(t, int64((k8sStartTimeout + time.Minute).Seconds()), *job.Spec.ActiveDeadlineSeconds)
}

func TestJobError(t *testing.T) {
	backoff := &batchv1.JobCondition{
		Type:    batchv1.JobFailed,
		Reason:  batchv1.JobReasonBackoffLimitExceeded,
		Message: "Job has reached the specified backoff limit",
	}
	deadline := &batchv1.JobCondition{Type: batchv1.JobFailed, Reason: batchv1.JobReasonDeadlineExceeded}

	require.NoError(t, jobError(nil, &ResultsSummary{Total: 2}))
	require.ErrorIs(t, jobError(nil, &ResultsSummary{}), ErrNoResults)
	require.NoError(t, jobError(backoff, &ResultsSummary{Total: 2, Errs: 1}),
		"failed tests fail the Job, and the results already say so")
	require.ErrorIs(t, jobError(backoff, &ResultsSummary{}), errJobFailed)
	require.ErrorIs(t, jobError(deadline, &ResultsSummary{Total: 2, Errs: 1}), errJobFailed)
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
		{name: "creating", init: []corev1.ContainerStatus{status("stage-tester-progs", exited(0))}, main: []corev1.ContainerStatus{status(k8sContainer, waiting("ContainerCreating"))}},
		{name: "evicted", phase: corev1.PodFailed, failed: true},
		{name: "running", main: []corev1.ContainerStatus{status(k8sContainer, running)}, started: true},
		{name: "tests failed", main: []corev1.ContainerStatus{status(k8sContainer, exited(1))}, started: true},
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
