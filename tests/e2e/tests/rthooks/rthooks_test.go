// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package rthooks_test contains e2e tests for the tetragon-rthooks DaemonSet.
package rthooks_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

const rthooksTriggerNamespace = "rthooks-trigger"

func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		WithInstallTetragon(
			tetragon.WithHelmOptions(map[string]string{
				"rthooks.enabled":            "true",
				"rthooks.interface":          "nri-hook",
				"rthooks.exportLogs.enabled": "true",
			}),
		).
		Init()

	if !flags.Opts.Minikube {
		klog.Warningf("This test is designed to run on Minikube and will be skipped. To run the test, use the -minikube flag.")
		return
	}

	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.DeleteNamespace(rthooksTriggerNamespace, true)(ctx, c)
		ctx, err := helpers.CreateNamespace(rthooksTriggerNamespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}
		return ctx, nil
	})

	runner.Run(m)
}

// TestRTHooksNRI verifies that:
//  1. The rthooks DaemonSet is healthy after installation.
//  2. Starting a pod in the test namespace causes tetragon-oci-hook to
//     successfully send a RuntimeHook request to the Tetragon agent.
func TestRTHooksNRI(t *testing.T) {
	const (
		rthooksDSName    = "tetragon-rthooks"
		rthooksNamespace = "kube-system"
		triggerPodName   = "rthooks-trigger"
	)

	runWorkload := features.New("Run workload to trigger rthooks").
		Assess("Start pod", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(rthooksTriggerNamespace, testPod, true)(ctx, c)
			if err != nil {
				t.Fatalf("failed to deploy test pod: %v", err)
			}
			return ctx
		}).
		Assess("Hook called successfully", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			client, err := c.NewClient()
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Find the rthooks pods.
			r := client.Resources(rthooksNamespace)
			podList := &corev1.PodList{}
			if err := r.List(ctx, podList,
				resources.WithLabelSelector("app.kubernetes.io/name="+rthooksDSName),
			); err != nil {
				t.Fatalf("failed to list rthooks pods: %v", err)
			}
			if len(podList.Items) == 0 {
				t.Fatal("no rthooks pods found")
			}

			// Retrieve the trigger pod to get its UID for log validation.
			triggerPod := &corev1.Pod{}
			if err := client.Resources(rthooksTriggerNamespace).Get(ctx, triggerPodName, rthooksTriggerNamespace, triggerPod); err != nil {
				t.Fatalf("failed to get trigger pod: %v", err)
			}
			podUID := string(triggerPod.UID)

			// Poll the export-logs sidecar stdout until we find a successful hook
			// request for our trigger pod, validating the pod metadata fields.
			deadline := time.Now().Add(2 * time.Minute)
			for time.Now().Before(deadline) {
				for _, pod := range podList.Items {
					logs, err := readExportLogs(ctx, client, rthooksNamespace, pod.Name)
					if err != nil {
						klog.Warningf("failed to read export-logs from %s: %v", pod.Name, err)
						continue
					}
					if findSuccessLogEntry(logs, triggerPodName, rthooksTriggerNamespace, podUID) {
						klog.Infof("rthooks: found success log entry for pod %s/%s (uid=%s)", rthooksTriggerNamespace, triggerPodName, podUID)
						return ctx
					}
				}
				time.Sleep(5 * time.Second)
			}
			t.Errorf("timed out waiting for success log entry for pod %s/%s", rthooksTriggerNamespace, triggerPodName)
			return ctx
		}).Feature()

	runner.Test(t, runWorkload)
}

// readExportLogs reads the current stdout of the export-logs sidecar container
// in the given rthooks pod via the Kubernetes log API.
func readExportLogs(ctx context.Context, client klient.Client, ns, podName string) (string, error) {
	const exportLogsContainer = "export-logs"

	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	if err != nil {
		return "", err
	}
	stream, err := clientSet.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{
		Container: exportLogsContainer,
	}).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	data, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// hookLogEntry represents the fields of a JSON log line written by tetragon-oci-hook.
type hookLogEntry struct {
	Msg           string `json:"msg"`
	PodName       string `json:"req-podName"`
	PodUID        string `json:"req-podUID"`
	PodNamespace  string `json:"req-podNamespace"`
	ContainerName string `json:"req-containerName"`
}

// findSuccessLogEntry scans newline-delimited JSON log output for a successful
// hook request matching the given pod name, namespace, and UID.
func findSuccessLogEntry(logs, podName, podNamespace, podUID string) bool {
	const hookSuccessMarker = "hook request to agent succeeded"

	for line := range strings.SplitSeq(logs, "\n") {
		if !strings.Contains(line, hookSuccessMarker) {
			continue
		}
		var entry hookLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Msg == hookSuccessMarker &&
			entry.PodName == podName &&
			entry.PodNamespace == podNamespace &&
			entry.PodUID == podUID {
			return true
		}
	}
	return false
}

const testPod = `
apiVersion: v1
kind: Pod
metadata:
  name: rthooks-trigger
  labels:
    app: rthooks-trigger
spec:
  containers:
    - name: sleep
      image: docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
      command: ["sh", "-c", "sleep 30"]
  restartPolicy: Never
`
