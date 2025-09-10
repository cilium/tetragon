// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// This package contains an end-to-end test for event labels.
package labels_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/cilium/tetragon/tests/e2e/metricschecker"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
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
		if err := manager.RunRepo(helm.WithArgs("add", "open-telemetry", "https://open-telemetry.github.io/opentelemetry-helm-charts")); err != nil {
			t.Fatalf("failed to add helm repo: %s", err)
		}

		if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
			t.Fatalf("failed to update helm repo: %s", err)
		}

		for range demoAppRetry {
			if err := manager.RunInstall(
				helm.WithName("otel-demo"),
				helm.WithChart("open-telemetry/opentelemetry-demo"),
				helm.WithVersion("0.30.3"),
				helm.WithNamespace(namespace),
				helm.WithArgs("--create-namespace"),
				helm.WithWait(),
			); err != nil {
				labelsChecker.ResetTimeout()
				t.Logf("failed to install demo app. run with `-args -v=4` for more context from helm: %s", err)
			} else {
				t.Log("demo app install successfully")
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
			helm.WithName("otel-demo"),
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

	metricsChecker := metricschecker.NewMetricsChecker("labelsMetricsChecker")
	metrics := features.New("Run Metrics Checks").
		Assess("Run Metrics Checks", metricsChecker.Greater("tetragon_events_total", 0)).Feature()

	// Spawn workload and run checker
	runner.TestInParallel(t, runEventChecker, runWorkload)
	runner.Test(t, metrics)
	runner.Test(t, uninstall)
}

func labelsEventChecker() *checker.RPCChecker {
	labelsEventChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("otel-demo-grafana").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/instance": *sm.Full("otel-demo"),
			"app.kubernetes.io/name":     *sm.Full("grafana"),
			"pod-template-hash":          *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-jaeger").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("all-in-one"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("jaeger"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-otelcol").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/instance": *sm.Full("otel-demo"),
			"app.kubernetes.io/name":     *sm.Full("otelcol"),
			"component":                  *sm.Full("standalone-collector"),
			"pod-template-hash":          *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-prometheus").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component":  *sm.Full("server"),
			"app.kubernetes.io/instance":   *sm.Full("otel-demo"),
			"app.kubernetes.io/managed-by": *sm.Full("Helm"),
			"app.kubernetes.io/name":       *sm.Full("prometheus"),
			"app.kubernetes.io/part-of":    *sm.Full("prometheus"),
			"pod-template-hash":            *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-accountingservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("accountingservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-accountingservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-accountingservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-adservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("adservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-adservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-adservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-cartservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("cartservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-cartservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-cartservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+")}))),
		ec.NewProcessExecChecker("otel-demo-checkoutservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("checkoutservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-checkoutservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-checkoutservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-currencyservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("currencyservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-currencyservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-currencyservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-emailservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("emailservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-emailservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-emailservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-flagd").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("flagd"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-flagd"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-flagd"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-frauddetectionservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("frauddetectionservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-frauddetectionservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-frauddetectionservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-frontend").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("frontend"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-frontend"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-frontend"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-frontendproxy").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("frontendproxy"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-frontendproxy"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-frontendproxy"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-kafka").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("kafka"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-kafka"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-kafka"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-loadgenerator").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("loadgenerator"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-loadgenerator"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-loadgenerator"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-paymentservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("paymentservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-paymentservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-paymentservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-productcatalogservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("productcatalogservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-productcatalogservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-productcatalogservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+")}))),
		ec.NewProcessExecChecker("otel-demo-quoteservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("quoteservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-quoteservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-quoteservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-recommendationservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("recommendationservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-recommendationservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-recommendationservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-redis").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("redis"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-redis"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-redis"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-shippingservice").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component": *sm.Full("shippingservice"),
			"app.kubernetes.io/instance":  *sm.Full("otel-demo"),
			"app.kubernetes.io/name":      *sm.Full("otel-demo-shippingservice"),
			"opentelemetry.io/name":       *sm.Full("otel-demo-shippingservice"),
			"pod-template-hash":           *sm.Regex("[a-f0-9]+"),
		}))),
		ec.NewProcessExecChecker("otel-demo-opensearch").WithProcess(ec.NewProcessChecker().WithPod(ec.NewPodChecker().WithPodLabels(map[string]sm.StringMatcher{
			"app.kubernetes.io/component":        *sm.Full("otel-demo-opensearch"),
			"app.kubernetes.io/instance":         *sm.Full("otel-demo"),
			"app.kubernetes.io/managed-by":       *sm.Full("Helm"),
			"app.kubernetes.io/name":             *sm.Full("opensearch"),
			"controller-revision-hash":           *sm.Prefix("otel-demo-opensearch"),
			"helm.sh/chart":                      *sm.Prefix("opensearch"),
			"statefulset.kubernetes.io/pod-name": *sm.Prefix("otel-demo-opensearch"),
		}))),
	)

	return checker.NewRPCChecker(labelsEventChecker, "labelsEventChecker")
}
