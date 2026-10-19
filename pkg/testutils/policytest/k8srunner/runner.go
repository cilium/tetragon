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
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

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
	// Logs receives the output of the tetra in the pod; nil drops it
	Logs io.Writer
}

// Runner runs the tests in a Job.
type Runner struct {
	conf *Conf
}

var _ policytest.Runner = (*Runner)(nil)

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

// Run runs the selection in a Job and returns the results once it has
// finished. The Job goes when Run returns.
func (r *Runner) Run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) (_ []*policytest.NamedResult, retErr error) {
	args, err := sel.Args()
	if err != nil {
		return nil, err
	}
	job, err := newJob(r.conf, args)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("failed to create namespace %q: %w", r.conf.Namespace, err)
	}

	jobs := r.conf.Client.BatchV1().Jobs(r.conf.Namespace)
	job, err = jobs.Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create job: %w", err)
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
		return nil, err
	}
	log.Debug("pod started", "name", pod)

	pods := r.conf.Client.CoreV1().Pods(r.conf.Namespace)
	if r.conf.Logs != nil {
		if err := copyLogs(ctx, r.conf.Logs, pods, pod); err != nil {
			return nil, err
		}
	}

	failed, err := waitForJobFinish(ctx, r.conf.Client, job)
	if err != nil {
		return nil, err
	}
	exitCode := 0
	if failed != nil {
		exitCode = containerExitCode(ctx, r.conf.Client, job.Namespace, pod)
	}
	var results []*policytest.NamedResult
	// the results container did not run when tetra could not
	if exitCode >= 0 {
		results, err = readResults(ctx, pods, pod)
		if err != nil {
			return results, fmt.Errorf("pod %s: %w", pod, err)
		}
	}
	summary := policytest.NewResultsSummary()
	for _, res := range results {
		summary.Update(res.Result)
	}
	return results, jobError(failed, exitCode, summary)
}

// copyLogs copies the output of tetra to w until tetra exits.
func copyLogs(ctx context.Context, w io.Writer, pods corev1client.PodInterface, pod string) error {
	logs, err := pods.GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		Follow:    true,
	}).Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs of pod %s: %w", pod, err)
	}
	defer logs.Close()
	if _, err := io.Copy(w, logs); err != nil {
		return fmt.Errorf("failed to copy logs of pod %s: %w", pod, err)
	}
	return nil
}

func readResults(ctx context.Context, pods corev1client.PodInterface, pod string) ([]*policytest.NamedResult, error) {
	out, err := pods.GetLogs(pod, &corev1.PodLogOptions{Container: resultsContainer}).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read the results: %w", err)
	}
	defer out.Close()
	return policytest.DecodeResults(out)
}
