// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultPollInterval = 2 * time.Second
	// cleanupTimeout bounds best-effort deletion of the test pod and the copied
	// TLS secret. Cleanup must run even when the caller's context is already
	// cancelled (timeout, Ctrl-C), so it uses a fresh context with this budget.
	cleanupTimeout = 30 * time.Second
)

// Orchestrator runs policy tests on a cluster by deploying a test pod, waiting
// for it to complete, collecting its machine-readable results from the pod
// logs, and cleaning the pod up.
type Orchestrator struct {
	client       kubernetes.Interface
	namespace    string
	pollInterval time.Duration

	// TLSSecretSourceNamespace is the namespace to copy a test pod's TLS secret
	// from (the agent's namespace). Secrets are namespace-scoped, so the secret
	// is copied into the test namespace and removed when the run finishes.
	TLSSecretSourceNamespace string

	// podLogs reads the logs of a completed pod. It is a field so tests can
	// inject log content (the fake clientset returns canned logs).
	podLogs func(ctx context.Context, namespace, name string) ([]byte, error)
}

// NewOrchestrator creates an Orchestrator that deploys test pods into namespace.
func NewOrchestrator(client kubernetes.Interface, namespace string) *Orchestrator {
	o := &Orchestrator{
		client:       client,
		namespace:    namespace,
		pollInterval: defaultPollInterval,
	}
	o.podLogs = o.readPodLogs
	return o
}

// Run creates the test pod, waits for it to complete, decodes the results from
// its logs, and deletes the pod. The pod is deleted on every exit path.
//
// Note: the policy is loaded and unloaded by the in-pod runner over gRPC, so it
// is not a Kubernetes object the orchestrator can delete. If the test pod dies
// before its own cleanup runs, the policy may leak in the agent.
// TODO: add a client-side policy backstop once the cleanup path for
// gRPC-loaded namespaced policies is decided.
func (o *Orchestrator) Run(ctx context.Context, spec *TestPodSpec) (results []TestResult, err error) {
	pod := spec.Build()

	if spec.TLSSecret != "" && o.TLSSecretSourceNamespace != "" && o.TLSSecretSourceNamespace != o.namespace {
		cleanup, err := o.copyTLSSecret(ctx, spec.TLSSecret)
		if err != nil {
			return nil, err
		}
		defer cleanup()
	}

	if _, err := o.client.CoreV1().Pods(o.namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("failed to create test pod: %w", err)
	}
	defer func() {
		cctx, cancel := cleanupContext()
		defer cancel()
		delErr := o.client.CoreV1().Pods(o.namespace).Delete(cctx, pod.Name, metav1.DeleteOptions{})
		if delErr != nil && err == nil {
			err = fmt.Errorf("failed to delete test pod %q: %w", pod.Name, delErr)
		}
	}()

	phase, err := o.waitForCompletion(ctx, pod.Name)
	if err != nil {
		return nil, err
	}

	logs, err := o.podLogs(ctx, o.namespace, pod.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to read test pod logs: %w", err)
	}

	results, err = ExtractResults(logs)
	if err != nil {
		if phase == corev1.PodFailed {
			return nil, fmt.Errorf("test pod %q failed; logs: %s", pod.Name, string(logs))
		}
		return nil, fmt.Errorf("failed to extract results from test pod %q: %w; logs: %s", pod.Name, err, string(logs))
	}
	return results, nil
}

// waitForCompletion polls the test pod until it has Succeeded or Failed, or the
// context is cancelled.
func (o *Orchestrator) waitForCompletion(ctx context.Context, name string) (corev1.PodPhase, error) {
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	for {
		pod, err := o.client.CoreV1().Pods(o.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get test pod %q: %w", name, err)
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			return pod.Status.Phase, nil
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timed out waiting for test pod %q: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

// copyTLSSecret copies the named secret from TLSSecretSourceNamespace into the
// orchestrator's namespace so the test pod can mount it (secrets are
// namespace-scoped). It returns a cleanup func that removes the copy.
func (o *Orchestrator) copyTLSSecret(ctx context.Context, name string) (func(), error) {
	src, err := o.client.CoreV1().Secrets(o.TLSSecretSourceNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS secret %s/%s: %w", o.TLSSecretSourceNamespace, name, err)
	}
	dup := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: o.namespace},
		Type:       src.Type,
		Data:       src.Data,
	}
	// Remove any copy stranded by a previous interrupted run so Create does not
	// fail with AlreadyExists (and the stale private key does not linger).
	_ = o.client.CoreV1().Secrets(o.namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if _, err := o.client.CoreV1().Secrets(o.namespace).Create(ctx, dup, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("failed to copy TLS secret into %q: %w", o.namespace, err)
	}
	return func() {
		cctx, cancel := cleanupContext()
		defer cancel()
		_ = o.client.CoreV1().Secrets(o.namespace).Delete(cctx, name, metav1.DeleteOptions{})
	}, nil
}

// cleanupContext returns a short-lived context for best-effort deletion that
// must run even when the caller's context is already cancelled (timeout,
// Ctrl-C). Callers must defer the returned cancel.
func cleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cleanupTimeout)
}

func (o *Orchestrator) readPodLogs(ctx context.Context, namespace, name string) ([]byte, error) {
	req := o.client.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{Container: containerName})
	return req.DoRaw(ctx)
}
