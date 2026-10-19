// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/pkg/testutils/policytest/k8sjob"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

const (
	namespace        = "policytest"
	testerProgsImage = "cilium/tetragon-tester-progs:latest"
	jobTimeout       = 5 * time.Minute
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

			runCtx, cancel := context.WithTimeout(ctx, jobTimeout)
			defer cancel()
			// pinned, so new policy tests do not change what this covers
			tests := []string{"kprobe-lseek", "tracepoint-exec"}
			var out bytes.Buffer
			err = k8sjob.Run(runCtx, cs, k8sjob.Opts{
				Namespace: namespace,
				Image:     testerProgsImage,
				Args:      append([]string{"--output=json", "--"}, tests...),
			}, io.MultiWriter(t.Output(), &out))
			require.NoError(t, err, "policy tests did not pass")
			require.ElementsMatch(t, tests, ranTests(t, &out), "not every test ran")

			return ctx
		}).Feature()

	runner.Test(t, feat)
}

func ranTests(t *testing.T, out *bytes.Buffer) []string {
	var ran []string
	for line := range strings.Lines(out.String()) {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var res struct {
			Name   string `json:"name"`
			Result struct {
				Skipped string `json:"skipped"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &res), "bad result line: %s", line)
		if res.Result.Skipped == "" {
			name, _, _ := strings.Cut(res.Name, " ")
			ran = append(ran, name)
		}
	}
	return ran
}

func loadImage(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	cluster := helpers.GetTempKindClusterName(ctx)
	if flags.Opts.Minikube {
		cluster = "minikube"
	}
	if cluster == "" {
		return ctx
	}
	ctx, err := envfuncs.LoadDockerImageToCluster(cluster, testerProgsImage)(ctx, cfg)
	require.NoError(t, err, "failed to load %s into the cluster", testerProgsImage)
	return ctx
}
