// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

const (
	namespace  = "policytest"
	jobTimeout = 5 * time.Minute
)

var runner *runners.Runner

func TestMain(m *testing.M) {
	// chart defaults expose the unix socket and enable the policy filter
	runner = runners.NewRunner().Init()
	runner.Run(m)
}

func TestPolicytestInPod(t *testing.T) {
	feat := features.New("policy tests run in a pod").
		Assess("the suite passes against the node-local agent", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			ctx = loadImage(ctx, t, cfg)
			t.Cleanup(func() {
				_, _ = helpers.DeleteNamespace(namespace, true)(context.Background(), cfg)
			})

			cs, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)

			log := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
			k8s, err := policytest.NewK8sRunner(ctx, log, &policytest.K8sConf{
				Client:    cs,
				Namespace: namespace,
				Image:     policytest.DefaultK8sImage,
				Timeout:   jobTimeout,
				Logs:      t.Output(),
			})
			require.NoError(t, err)
			defer k8s.Close()

			// pinned, so new policy tests do not change what this covers
			sel := &policytest.Selection{Names: []string{"kprobe-lseek", "tracepoint-exec"}}

			var results []*policytest.NamedResult
			var ran []string
			for res, err := range k8s.Run(ctx, log, sel) {
				require.NoError(t, err, "policy tests did not run")
				results = append(results, res)
				name, _, _ := strings.Cut(res.Name, " ")
				ran = append(ran, name)
			}
			policytest.DumpResults(t.Output(), results)
			for _, res := range results {
				require.Empty(t, res.Result.Skipped, "%s was skipped", res.Name)
				require.NoError(t, res.Result.Err.Err, "%s failed", res.Name)
				for _, sc := range res.Result.ScenariosRes {
					require.NoError(t, sc.Err(), "%s: scenario %q failed", res.Name, sc.Name)
				}
			}
			require.ElementsMatch(t, sel.Names, ran, "not every test ran")

			return ctx
		}).Feature()

	runner.Test(t, feat)
}

func loadImage(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	cluster := helpers.GetTempKindClusterName(ctx)
	if flags.Opts.Minikube {
		cluster = "minikube"
	}
	if cluster == "" {
		return ctx
	}
	ctx, err := envfuncs.LoadDockerImageToCluster(cluster, policytest.DefaultK8sImage)(ctx, cfg)
	require.NoError(t, err, "failed to load %s into the cluster", policytest.DefaultK8sImage)
	return ctx
}
