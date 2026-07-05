// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package policytest_test runs a Tetragon policy test from inside the cluster
// (the `tetra policytest run --kube` flow) and asserts it passes.
package policytest_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/pkg/testutils/policytest/kube"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

const (
	policytestImage = "cilium/tetragon-policytest:latest"
	testNamespace   = "policytest-e2e"
	// policyTest is a benign, observe-only registered policy test.
	policyTest = "kprobe-lseek"
)

var runner *runners.Runner

func TestMain(m *testing.M) {
	r := runners.NewRunner()
	if os.Getenv("POLICYTEST_E2E_USE_EXISTING") != "" {
		// Target an already-installed Tetragon (e.g. a dev cluster from
		// -kubeconfig): skip install, port-forward, AND uninstall, so the
		// existing Tetragon is left untouched. UninstallTetragon must be set
		// before Init parses flags and registers the teardown hook.
		flags.Opts.UninstallTetragon = false
		r = r.WithInstallTetragonFn(func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			return ctx, nil
		}).NoPortForward()
	} else {
		// The chart serves gRPC over a unix socket by default; the test pod
		// needs a TCP listener reachable on the node, so bind to all interfaces.
		r = r.WithInstallTetragon(tetragon.WithHelmOptions(map[string]string{
			"tetragon.grpc.address":       "0.0.0.0:54321",
			"tetragon.exportAllowList":    "",
			"tetragon.enablePolicyFilter": "true",
		}))
	}
	runner = r.Init()
	runner.Run(m)
}

func TestPolicytestRunKube(t *testing.T) {
	feat := features.New("policytest run --kube").
		Assess("benign policy test passes from a test pod", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := kube.NewClient(cfg.KubeconfigFile())
			require.NoError(t, err)

			// Load the policytest image into a framework-created kind cluster.
			// For an existing cluster it must be pre-loaded (kind load).
			if name := helpers.GetTempKindClusterName(ctx); name != "" {
				ctx, err = envfuncs.LoadDockerImageToCluster(name, policytestImage)(ctx, cfg)
				require.NoError(t, err)
			}

			agentNamespace := flags.Opts.Helm.Namespace
			tlsSecret := os.Getenv("POLICYTEST_E2E_TLS_SECRET")

			// Fresh throwaway namespace for the test pod and namespaced policy.
			_ = client.CoreV1().Namespaces().Delete(ctx, testNamespace, metav1.DeleteOptions{})
			_, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = client.CoreV1().Namespaces().Delete(context.Background(), testNamespace, metav1.DeleteOptions{})
			})

			agent, err := kube.DiscoverAgent(ctx, client, agentNamespace, "app.kubernetes.io/name=tetragon", "")
			require.NoError(t, err)

			spec := &kube.TestPodSpec{
				Name:          "policytest-e2e",
				Namespace:     testNamespace,
				Node:          agent.Node,
				Image:         policytestImage,
				RunID:         "e2e",
				AgentAddr:     fmt.Sprintf("%s:54321", agent.PodIP),
				Tests:         []string{policyTest},
				TLSSecret:     tlsSecret,
				TLSServerName: "tetragon.local",
			}
			orch := kube.NewOrchestrator(client, testNamespace)
			orch.TLSSecretSourceNamespace = agentNamespace

			results, err := orch.Run(ctx, spec)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Falsef(t, results[0].Failed(), "policy test %q should pass", policyTest)

			return ctx
		}).Feature()

	runner.Test(t, feat)
}
