// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package policytest

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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// DefaultK8sImage is the tester-progs image that `make image-tester-progs` builds.
const DefaultK8sImage = "cilium/tetragon-tester-progs:latest"

var (
	errK8sNoNamespace = errors.New("no namespace for the policytest job")
	errK8sNoImage     = errors.New("no image for the policytest job")
)

// K8sConf configures K8sRunner.
type K8sConf struct {
	// Client for the cluster; nil loads the kubeconfig
	Client kubernetes.Interface
	// KubeContext is the kubeconfig context to use; empty means the current one
	KubeContext string
	// Namespace for the Job, created if missing
	Namespace string
	// Image with tetra and the tester programs
	Image string
	// Node to run the Job on; empty lets the scheduler pick one
	Node string
	// ExtraArgs are passed to the tetra in the pod ahead of the selection
	ExtraArgs []string
	// Timeout for the tests; zero means no limit. The Job gets
	// k8sStartTimeout on top.
	Timeout time.Duration
	// Logs receives the pod output that is not a result; nil drops it
	Logs io.Writer
}

// K8sRunner runs the tests in a Job next to the node-local agent. The Job
// runs `tetra policytest run --output json` from the tester-progs image and
// the results stream back through the pod logs.
type K8sRunner struct {
	cs   kubernetes.Interface
	conf *K8sConf
}

// NewK8sRunner connects to the cluster and returns a runner for it. It works
// on a copy of conf.
func NewK8sRunner(ctx context.Context, log *slog.Logger, conf *K8sConf) (*K8sRunner, error) {
	switch {
	case conf.Namespace == "":
		return nil, errK8sNoNamespace
	case conf.Image == "":
		return nil, errK8sNoImage
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
	if _, err := cs.Discovery().RESTClient().Get().AbsPath("/version").DoRaw(ctx); err != nil {
		return nil, fmt.Errorf("failed to reach the cluster: %w", err)
	}
	log.Debug("connected to the cluster", "namespace", conf.Namespace)

	c := *conf
	return &K8sRunner{cs: cs, conf: &c}, nil
}

// Close has nothing to release: the Job goes when Run returns.
func (r *K8sRunner) Close() error {
	return nil
}

// Run runs the selection in a Job and yields the results as the pod reports
// them.
func (r *K8sRunner) Run(ctx context.Context, log *slog.Logger, sel *Selection) iter.Seq2[*NamedResult, error] {
	return func(yield func(*NamedResult, error) bool) {
		stopped := false
		err := r.run(ctx, log, sel, func(res *NamedResult) bool {
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

// run creates the Job, yields the results it streams and deletes it.
func (r *K8sRunner) run(
	ctx context.Context, log *slog.Logger, sel *Selection,
	yield func(*NamedResult) bool,
) (retErr error) {
	if err := sel.Validate(); err != nil {
		return err
	}
	job, err := newK8sJob(r.conf, sel.Args())
	if err != nil {
		return err
	}
	if r.conf.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, k8sStartTimeout+r.conf.Timeout)
		defer cancel()
	}

	_, err = r.cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		Name: r.conf.Namespace,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %q: %w", r.conf.Namespace, err)
	}

	jobs := r.cs.BatchV1().Jobs(r.conf.Namespace)
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

	pod, err := waitForPodStart(ctx, r.cs, job)
	if err != nil {
		return err
	}
	log.Debug("pod started", "name", pod)

	logs, err := r.cs.CoreV1().Pods(r.conf.Namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: k8sContainer,
		Follow:    true,
	}).Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to stream logs of pod %s: %w", pod, err)
	}
	defer logs.Close()

	summary := NewResultsSummary()
	for res, err := range DecodeResults(logs, r.conf.Logs) {
		if err != nil {
			return fmt.Errorf("pod %s: %w", pod, err)
		}
		summary.Update(res.Result)
		if !yield(res) {
			return nil
		}
	}

	failed, err := waitForJobFinish(ctx, r.cs, job)
	if err != nil {
		return err
	}
	return jobError(failed, summary)
}
