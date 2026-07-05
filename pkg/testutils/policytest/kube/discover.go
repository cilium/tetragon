// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// DefaultAgentLabelSelector selects Tetragon agent pods. Tetragon's Helm chart
// labels the agent DaemonSet pods with app.kubernetes.io/name=<daemonset-name>,
// "tetragon" by default.
const DefaultAgentLabelSelector = "app.kubernetes.io/name=tetragon"

// NewClient builds a Kubernetes clientset from the operator's ambient
// kubeconfig. If kubeconfig is empty, the default loading rules are used
// (KUBECONFIG env / ~/.kube/config).
func NewClient(kubeconfig string) (kubernetes.Interface, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return client, nil
}

// Agent identifies a discovered Tetragon agent pod and the node it runs on.
type Agent struct {
	Node    string
	PodName string
	PodIP   string
}

// DiscoverAgent finds a Ready Tetragon agent pod in namespace, selected by
// labelSelector. When node is non-empty, the agent must run on that node. The
// test pod will be co-located on the returned node so it can reach the agent
// locally.
func DiscoverAgent(
	ctx context.Context, client kubernetes.Interface,
	namespace, labelSelector, node string,
) (*Agent, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list agent pods: %w", err)
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if node != "" && pod.Spec.NodeName != node {
			continue
		}
		if !podReady(pod) {
			continue
		}
		return &Agent{
			Node:    pod.Spec.NodeName,
			PodName: pod.Name,
			PodIP:   pod.Status.PodIP,
		}, nil
	}

	if node != "" {
		return nil, fmt.Errorf("no ready Tetragon agent found on node %q (namespace %q, selector %q)", node, namespace, labelSelector)
	}
	return nil, fmt.Errorf("no ready Tetragon agent found (namespace %q, selector %q)", namespace, labelSelector)
}

func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
