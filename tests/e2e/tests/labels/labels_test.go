// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// This package contains an end-to-end test for event labels.
package labels_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

// This holds our test environment which we get from calling runners.NewRunner().Setup()
var runner *runners.Runner

const (
	// The namespace where we want to spawn our pods
	namespace    = "labels"
	demoAppRetry = 3
)

func installDemoApp(labelsChecker *checker.RPCChecker) features.Func {
	return func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
		manager := helm.New(c.KubeconfigFile())
		if err := manager.RunRepo(helm.WithArgs("add", "isovalent", "https://helm.isovalent.com")); err != nil {
			t.Fatalf("failed to add helm repo: %s", err)
		}

		if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
			t.Fatalf("failed to update helm repo: %s", err)
		}

		for i := 0; i < demoAppRetry; i++ {
			if err := manager.RunInstall(
				helm.WithName("jobs-app"),
				helm.WithChart("isovalent/jobs-app"),
				helm.WithVersion("v0.7.1"),
				helm.WithNamespace(namespace),
				helm.WithArgs("--create-namespace", "--wait"),
			); err != nil {
				labelsChecker.ResetTimeout()
				t.Logf("failed to install demo app. run with `-args -v=4` for more context from helm: %s", err)
			} else {
				return ctx
			}
		}

		t.Fatalf("failed to install demo app after %d tries", demoAppRetry)
		return ctx
	}
}

func uninstallDemoApp() features.Func {
	return func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
		manager := helm.New(c.KubeconfigFile())
		if err := manager.RunUninstall(
			helm.WithName("jobs-app"),
			helm.WithNamespace(namespace),
		); err != nil {
			t.Fatalf("failed to uninstall demo app. run with `-args -v=4` for more context from helm: %s", err)
		}
		return ctx
	}
}

func TestMain(m *testing.M) {
	runner = runners.NewRunner().Init()

	// Here we ensure our test namespace doesn't already exist then create it.
	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, c)

		ctx, err := helpers.CreateNamespace(namespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}

		return ctx, nil
	})

	// Run the tests using the test runner.
	runner.Run(m)
}

func TestLabelsDemoApp(t *testing.T) {
	if os.Getenv("GHA_OS") == "ubuntu-22.04-arm64" {
		t.Skip("Skipping, see: ://github.com/cilium/tetragon/issues/3060")
	}

	// Must be called at the beginning of every test
	runner.SetupExport(t)

	labelsChecker := labelsEventChecker().WithEventLimit(5000).WithTimeLimit(5 * time.Minute)

	// This starts labelsChecker and uses it to run event checks.
	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks", labelsChecker.CheckInNamespace(1*time.Minute, namespace)).Feature()

	// This feature waits for labelsChecker to start then runs a custom workload.
	runWorkload := features.New("Run Workload").
		/* Wait up to 30 seconds for the event checker to start before continuing */
		Assess("Wait for Checker", labelsChecker.Wait(30*time.Second)).
		/* Run the workload */
		Assess("Run Workload", installDemoApp(labelsChecker)).
		Feature()

	uninstall := features.New("Uninstall Demo App").
		Assess("Uninstall", uninstallDemoApp()).Feature()

	// Spawn workload and run checker
	runner.TestInParallel(t, runEventChecker, runWorkload)
	runner.Test(t, uninstall)
}

func labelsEventChecker() *checker.RPCChecker {
	labelsEventChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("coreapi").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("coreapi"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("crawler").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("crawler"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("elasticsearch").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":                                *sm.Full("elasticsearch-master"),
			"chart":                              *sm.Full("elasticsearch"),
			"controller-revision-hash":           *sm.Regex("elasticsearch-master-[a-f0-9]+"),
			"release":                            *sm.Full("jobs-app"),
			"statefulset.kubernetes.io/pod-name": *sm.Prefix("elasticsearch-master"),
		}))),
		ec.NewProcessExecChecker("jobposting").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("jobposting"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("kafka").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/instance":         *sm.Full("jobs-app"),
			"app.kubernetes.io/managed-by":       *sm.Full("strimzi-cluster-operator"),
			"app.kubernetes.io/name":             *sm.Full("kafka"),
			"app.kubernetes.io/part-of":          *sm.Full("strimzi-jobs-app"),
			"statefulset.kubernetes.io/pod-name": *sm.Prefix("jobs-app-kafka"),
			"strimzi.io/controller":              *sm.Full("strimzipodset"),
			"strimzi.io/controller-name":         *sm.Full("jobs-app-kafka"),
			"strimzi.io/cluster":                 *sm.Full("jobs-app"),
			"strimzi.io/kind":                    *sm.Full("Kafka"),
			"strimzi.io/name":                    *sm.Full("jobs-app-kafka"),
			"strimzi.io/pod-name":                *sm.Prefix("jobs-app-kafka"),
		}))),
		ec.NewProcessExecChecker("zookeeper").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/instance":         *sm.Full("jobs-app"),
			"app.kubernetes.io/managed-by":       *sm.Full("strimzi-cluster-operator"),
			"app.kubernetes.io/name":             *sm.Full("zookeeper"),
			"app.kubernetes.io/part-of":          *sm.Full("strimzi-jobs-app"),
			"statefulset.kubernetes.io/pod-name": *sm.Prefix("jobs-app-zookeeper"),
			"strimzi.io/cluster":                 *sm.Full("jobs-app"),
			"strimzi.io/controller":              *sm.Full("strimzipodset"),
			"strimzi.io/controller-name":         *sm.Full("jobs-app-zookeeper"),
			"strimzi.io/kind":                    *sm.Full("Kafka"),
			"strimzi.io/name":                    *sm.Full("jobs-app-zookeeper"),
			"strimzi.io/pod-name":                *sm.Prefix("jobs-app-zookeeper"),
		}))),
		ec.NewProcessExecChecker("loader").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("loader"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("recruiter").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app":               *sm.Full("recruiter"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("cluster-operator").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"name":              *sm.Full("strimzi-cluster-operator"),
			"pod-template-hash": *sm.Regex("[a-f0-9]+"),
			"strimzi.io/kind":   *sm.Full("cluster-operator"),
		}))),
	)

	return checker.NewRPCChecker(labelsEventChecker, "labelsEventChecker")
}
