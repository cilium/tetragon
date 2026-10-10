// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package policytest_test runs `tetra policytest run` from a pod
// (examples/policytest/job.yaml) and asserts that the suite passes.
package policytest_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

const (
	namespace = "policytest"
	jobDir    = "../../../../examples/policytest"
	// built by make image-policytest; loaded into a cluster this run creates
	policytestImage = "cilium/tetragon-policytest:latest"
	jobTimeout      = 5 * time.Minute
)

var (
	runner       *runners.Runner
	errJobFailed = errors.New("policytest job failed")
)

func TestMain(m *testing.M) {
	// chart defaults already expose the unix socket and enable the policy filter
	runner = runners.NewRunner().Init()
	runner.Run(m)
}

func TestPolicytestInPod(t *testing.T) {
	feat := features.New("policy tests run in a pod").
		Assess("the suite passes against the node-local agent", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			ctx = loadImage(ctx, t, cfg)

			ctx, err := helpers.CreateNamespace(namespace, true)(ctx, cfg)
			t.Cleanup(func() {
				_, _ = helpers.DeleteNamespace(namespace, true)(context.Background(), cfg)
			})
			require.NoError(t, err, "failed to create namespace")

			job := loadJob(t)
			ctx, err = helpers.LoadObjects(namespace, []k8s.Object{job}, false)(ctx, cfg)
			require.NoError(t, err, "failed to create the policytest job")

			// fail fast on a failed job instead of waiting out the timeout
			conds := conditions.New(cfg.Client().Resources(namespace))
			err = wait.For(func(ctx context.Context) (bool, error) {
				failed, err := conds.JobFailed(job)(ctx)
				if err != nil {
					return false, err
				}
				if failed {
					return false, errJobFailed
				}
				return conds.JobCompleted(job)(ctx)
			}, wait.WithContext(ctx), wait.WithTimeout(jobTimeout))
			if err != nil {
				t.Log(jobLogs(ctx, cfg))
			}
			require.NoError(t, err, "policy tests did not pass")

			return ctx
		}).Feature()

	runner.Test(t, feat)
}

// loadImage loads the policytest image into a cluster this run created, as
// the Tetragon install does for the agent image.
func loadImage(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	cluster := helpers.GetTempKindClusterName(ctx)
	if flags.Opts.Minikube {
		cluster = "minikube"
	}
	if cluster == "" {
		return ctx
	}
	ctx, err := envfuncs.LoadDockerImageToCluster(cluster, policytestImage)(ctx, cfg)
	require.NoError(t, err, "failed to load %s into the cluster", policytestImage)
	return ctx
}

// loadJob reads the example Job and pins its test list, so this test breaks
// when the plumbing breaks rather than when a new policy test lands.
func loadJob(t *testing.T) *batchv1.Job {
	var job batchv1.Job
	require.NoError(t, decoder.DecodeFile(os.DirFS(jobDir), "job.yaml", &job))

	args := job.Spec.Template.Spec.Containers[0].Args
	i := slices.Index(args, "--all-tests")
	require.NotEqual(t, -1, i, "job.yaml does not pass --all-tests")
	job.Spec.Template.Spec.Containers[0].Args = slices.Replace(args, i, i+1, "kprobe-lseek", "tracepoint-exec", "lsm-dup-hooks")
	return &job
}

// jobLogs returns the logs of every container of the job's pods, which the
// namespace cleanup would otherwise take with it.
func jobLogs(ctx context.Context, cfg *envconf.Config) string {
	cs, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return err.Error()
	}
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=tetragon-policytest"})
	if err != nil {
		return err.Error()
	}
	var sb strings.Builder
	for _, pod := range pods.Items {
		for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
			fmt.Fprintf(&sb, "=== %s/%s ===\n", pod.Name, c.Name)
			out, err := cs.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: c.Name}).Do(ctx).Raw()
			if err != nil {
				fmt.Fprintln(&sb, err)
				continue
			}
			sb.Write(out)
		}
	}
	return sb.String()
}
