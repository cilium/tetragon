// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package k8sjob runs the policy tests as a Kubernetes Job.
package k8sjob

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

const (
	container    = "policytest"
	pollInterval = time.Second
	startTimeout = 5 * time.Minute
)

var (
	//go:embed job.yaml
	jobYAML []byte

	errJobFailed  = errors.New("policytest job failed")
	errPodFailed  = errors.New("policytest pod failed to start")
	errNoTestArgs = errors.New("no tests selected")
)

type Opts struct {
	Namespace string
	Image     string
	Node      string
	Args      []string
	// Zero means no limit
	Timeout time.Duration
}

func NewJob(opts Opts) (*batchv1.Job, error) {
	if len(opts.Args) == 0 {
		return nil, errNoTestArgs
	}
	var job batchv1.Job
	if err := yaml.UnmarshalStrict(jobYAML, &job); err != nil {
		return nil, fmt.Errorf("failed to decode job template: %w", err)
	}
	job.Namespace = opts.Namespace
	spec := &job.Spec.Template.Spec
	spec.NodeName = opts.Node
	spec.InitContainers[0].Image = opts.Image
	spec.Containers[0].Image = opts.Image
	spec.Containers[0].Args = append(spec.Containers[0].Args, opts.Args...)
	if opts.Timeout > 0 {
		job.Spec.ActiveDeadlineSeconds = new(int64((startTimeout + opts.Timeout).Seconds()))
	}
	return &job, nil
}

func Run(ctx context.Context, cs kubernetes.Interface, opts Opts, out io.Writer) (retErr error) {
	job, err := NewJob(opts)
	if err != nil {
		return err
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, startTimeout+opts.Timeout)
		defer cancel()
	}

	_, err = cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		Name: opts.Namespace,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %q: %w", opts.Namespace, err)
	}

	jobs := cs.BatchV1().Jobs(opts.Namespace)
	job, err = jobs.Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create job: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		policy := metav1.DeletePropagationBackground
		err := jobs.Delete(ctx, job.Name, metav1.DeleteOptions{PropagationPolicy: &policy})
		if err != nil && !apierrors.IsNotFound(err) {
			retErr = errors.Join(retErr, fmt.Errorf("failed to delete job %s: %w", job.Name, err))
		}
	}()

	pod, err := waitForStart(ctx, cs, job)
	if err != nil {
		return err
	}

	logs, err := cs.CoreV1().Pods(opts.Namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		Follow:    true,
	}).Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs of pod %s: %w", pod, err)
	}
	defer logs.Close()
	if _, err := io.Copy(out, logs); err != nil {
		return fmt.Errorf("failed to stream logs of pod %s: %w", pod, err)
	}

	return waitForFinish(ctx, cs, job)
}

func waitForStart(ctx context.Context, cs kubernetes.Interface, job *batchv1.Job) (string, error) {
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

func waitForFinish(ctx context.Context, cs kubernetes.Interface, job *batchv1.Job) error {
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
		return fmt.Errorf("failed to wait for job %s: %w", job.Name, errors.Join(err, lastErr))
	}
	if failed != nil {
		return fmt.Errorf("%w: %s", errJobFailed, failed.Reason)
	}
	return nil
}
