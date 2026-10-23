// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package k8srunner runs the policy tests in a Kubernetes Job next to the
// node-local agent.
package k8srunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// DefaultImage is the tester-progs image that `make image-tester-progs` builds.
const DefaultImage = "cilium/tetragon-tester-progs:latest"

var (
	errNoNamespace = errors.New("no namespace for the policytest job")
	errNoImage     = errors.New("no image for the policytest job")
)

// Conf configures Runner.
type Conf struct {
	// Client for the cluster; nil loads the kubeconfig
	Client kubernetes.Interface
	// KubeContext is the kubeconfig context to use; empty means the current one
	KubeContext string
	// Namespace for the Job, created if missing
	Namespace string
	Image     string
	Node      string
	// ExtraArgs are passed to the tetra in the pod ahead of the selection
	ExtraArgs []string
	// Timeout for the tests; zero means no limit
	Timeout time.Duration
	// Logs receives the pod output that is not a result; nil drops it
	Logs io.Writer
}

// Runner runs the tests in a Job.
type Runner struct {
	conf *Conf
}

// New connects to the cluster and returns a runner for it. It works
// on a copy of conf.
func New(ctx context.Context, log *slog.Logger, conf *Conf) (*Runner, error) {
	switch {
	case conf.Namespace == "":
		return nil, errNoNamespace
	case conf.Image == "":
		return nil, errNoImage
	}

	cs := conf.Client
	if cs == nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		overrides := &clientcmd.ConfigOverrides{CurrentContext: conf.KubeContext}
		cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}
		cs, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
		}
	}

	// every authenticated user may read the version, so this only tells
	// whether the cluster answers
	if _, err := discovery.ToDiscoveryInterfaceWithContext(cs.Discovery()).ServerVersionWithContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to reach the cluster: %w", err)
	}
	log.Debug("connected to the cluster", "namespace", conf.Namespace)

	c := *conf
	c.Client = cs
	return &Runner{conf: &c}, nil
}

// Close has nothing to release: the Job goes when Run returns.
func (r *Runner) Close() error {
	return nil
}

func (r *Runner) Run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) iter.Seq2[*policytest.NamedResult, error] {
	return func(yield func(*policytest.NamedResult, error) bool) {
		stopped := false
		err := r.run(ctx, log, sel, func(res *policytest.NamedResult) bool {
			stopped = !yield(res, nil)
			return !stopped
		})
		if err == nil {
			return
		}
		if stopped {
			// the iterator contract forbids another yield
			log.Warn("failed to finish the job after the consumer stopped", logfields.Error, err)
			return
		}
		yield(nil, err)
	}
}

func (r *Runner) run(
	ctx context.Context, log *slog.Logger, sel *policytest.Selection,
	yield func(*policytest.NamedResult) bool,
) (retErr error) {
	args, err := sel.Args()
	if err != nil {
		return err
	}
	job, err := newJob(r.conf, args)
	if err != nil {
		return err
	}
	if r.conf.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, startTimeout+r.conf.Timeout)
		defer cancel()
	}

	_, err = r.conf.Client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		Name: r.conf.Namespace,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %q: %w", r.conf.Namespace, err)
	}

	jobs := r.conf.Client.BatchV1().Jobs(r.conf.Namespace)
	job, err = jobs.Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create job: %w", err)
	}
	log.Debug("job created", "namespace", job.Namespace, "name", job.Name)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		policy := metav1.DeletePropagationBackground
		err := jobs.Delete(ctx, job.Name, metav1.DeleteOptions{PropagationPolicy: &policy})
		if err != nil && !apierrors.IsNotFound(err) {
			retErr = errors.Join(retErr, fmt.Errorf("failed to delete job %s: %w", job.Name, err))
		}
	}()

	pod, err := waitForPodStart(ctx, r.conf.Client, job)
	if err != nil {
		return err
	}
	log.Debug("pod started", "name", pod)

	logs, err := r.conf.Client.CoreV1().Pods(r.conf.Namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		Follow:    true,
	}).Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs of pod %s: %w", pod, err)
	}
	defer logs.Close()

	summary := policytest.NewResultsSummary()
	for res, err := range policytest.DecodeResults(logs, r.conf.Logs) {
		if err != nil {
			return fmt.Errorf("pod %s: %w", pod, err)
		}
		summary.Update(res.Result)
		if !yield(res) {
			return nil
		}
	}

	failed, err := waitForJobFinish(ctx, r.conf.Client, job)
	if err != nil {
		return err
	}
	exitCode := 0
	if failed != nil {
		exitCode = containerExitCode(ctx, r.conf.Client, job.Namespace, pod)
	}
	return jobError(failed, exitCode, summary)
}
