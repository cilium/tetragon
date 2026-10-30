// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package k8srunner

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

const (
	container    = "policytest"
	pollInterval = time.Second
	startTimeout = 5 * time.Minute
)

var (
	//go:embed job.yaml
	jobYAML []byte

	errJobFailed = errors.New("policytest job failed")
	errPodFailed = errors.New("policytest pod failed to start")
)

func newJob(conf *Conf, args []string) (*batchv1.Job, error) {
	var job batchv1.Job
	if err := yaml.UnmarshalStrict(jobYAML, &job); err != nil {
		return nil, fmt.Errorf("failed to decode job template: %w", err)
	}
	job.Namespace = conf.Namespace
	spec := &job.Spec.Template.Spec
	spec.NodeName = conf.Node
	spec.InitContainers[0].Image = conf.Image
	spec.Containers[0].Image = conf.Image
	spec.Containers[0].Args = append(spec.Containers[0].Args, conf.ExtraArgs...)
	spec.Containers[0].Args = append(spec.Containers[0].Args, args...)
	if conf.Timeout > 0 {
		job.Spec.ActiveDeadlineSeconds = new(int64((startTimeout + conf.Timeout).Seconds()))
	}
	return &job, nil
}

func waitForPodStart(ctx context.Context, cs kubernetes.Interface, job *batchv1.Job) (string, error) {
	var name string
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, pollInterval, startTimeout, true, func(ctx context.Context) (bool, error) {
		pods, err := cs.CoreV1().Pods(job.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: batchv1.JobNameLabel + "=" + job.Name,
		})
		if err != nil {
			lastErr = err
			return false, nil
		}
		if len(pods.Items) == 0 {
			return false, nil
		}
		pod := &pods.Items[0]
		started, err := podStarted(pod)
		name = pod.Name
		return started, err
	})
	if err != nil {
		return "", fmt.Errorf("pod of job %s did not start: %w", job.Name, errors.Join(err, lastErr))
	}
	return name, nil
}

func podStarted(pod *corev1.Pod) (bool, error) {
	if pod.Status.Phase == corev1.PodFailed {
		return false, fmt.Errorf("%w: %s: %s", errPodFailed, pod.Status.Reason, pod.Status.Message)
	}
	for _, s := range slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses) {
		if w := s.State.Waiting; w != nil {
			switch w.Reason {
			case "ErrImagePull", "ImagePullBackOff", "ErrImageNeverPull", "InvalidImageName", "CreateContainerConfigError":
				return false, fmt.Errorf("%w: %s: %s: %s", errPodFailed, s.Name, w.Reason, w.Message)
			}
		}
		if t := s.State.Terminated; t != nil && t.ExitCode != 0 && s.Name != container {
			return false, fmt.Errorf("%w: %s exited with %d: %s", errPodFailed, s.Name, t.ExitCode, t.Message)
		}
		if s.Name == container && (s.State.Running != nil || s.State.Terminated != nil) {
			return true, nil
		}
	}
	return false, nil
}

// waitForJobFinish returns the Failed condition of the job, or nil once it
// has completed.
func waitForJobFinish(ctx context.Context, cs kubernetes.Interface, job *batchv1.Job) (*batchv1.JobCondition, error) {
	var failed *batchv1.JobCondition
	var lastErr error
	err := wait.PollUntilContextCancel(ctx, pollInterval, true, func(ctx context.Context) (bool, error) {
		j, err := cs.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}
		for _, c := range j.Status.Conditions {
			if c.Status != corev1.ConditionTrue {
				continue
			}
			switch c.Type {
			case batchv1.JobComplete:
				return true, nil
			case batchv1.JobFailed:
				failed = &c
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to wait for job %s: %w", job.Name, errors.Join(err, lastErr))
	}
	return failed, nil
}

// jobError maps the end of the Job to EndError.
func jobError(failed *batchv1.JobCondition, exitCode int, summary *policytest.ResultsSummary) error {
	if failed == nil {
		return summary.EndError(0, nil)
	}
	return summary.EndError(exitCode, fmt.Errorf("%w: %s: %s", errJobFailed, failed.Reason, failed.Message))
}

// containerExitCode returns the exit code of the tetra container, or -1 when
// it is unknown.
func containerExitCode(ctx context.Context, cs kubernetes.Interface, namespace, pod string) int {
	p, err := cs.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return -1
	}
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == container && s.State.Terminated != nil {
			return int(s.State.Terminated.ExitCode)
		}
	}
	return -1
}
