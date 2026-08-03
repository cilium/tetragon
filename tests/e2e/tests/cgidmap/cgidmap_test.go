// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package cgidmap_test verifies that with cgidmap enabled and the CRI
// disabled, pod association for pods that pre-exist the agent comes from the
// cgroupfs-scan fallback resolver.
package cgidmap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/metricschecker"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

const (
	namespace = "cgidmap-fallback"
	podName   = "cgidmap-workload"
)

// workloadPod execs repeatedly so exec events keep arriving after the
// fallback resolver has populated cgidmap. The container id is resolved once
// per event, so a single exec could race the resolver and stay unassociated.
const workloadPod = `
apiVersion: v1
kind: Pod
metadata:
  name: cgidmap-workload
  labels:
    app: cgidmap-workload
spec:
  containers:
    - name: workload
      image: docker.io/library/alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
      command: ["sh", "-c", "while true; do uname -a; sleep 2; done"]
  restartPolicy: Never
`

func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		// The workload pod must exist BEFORE the agent starts so that pod
		// association can only come from the cgroupfs fallback: rthooks are
		// disabled (and would not cover pre-existing containers anyway) and
		// the CRI is disabled.
		WithInstallTetragonFn(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			ctx, _ = helpers.DeleteNamespace(namespace, true)(ctx, cfg)
			ctx, err := helpers.CreateNamespace(namespace, true)(ctx, cfg)
			if err != nil {
				return ctx, fmt.Errorf("failed to create namespace: %w", err)
			}
			ctx, err = helpers.LoadCRDString(namespace, workloadPod, true)(ctx, cfg)
			if err != nil {
				return ctx, fmt.Errorf("failed to create workload pod: %w", err)
			}
			return tetragon.Install(
				tetragon.WithHelmOptions(map[string]string{
					"tetragon.exportAllowList": "",
					"tetragon.cgidmap.enabled": "true",
					// tetragon.cri.enabled stays false (chart default)
				}),
			)(ctx, cfg)
		}).
		Init()

	runner.Run(m)
}

// TestCgidmapCgroupfsFallback verifies that exec events from the
// pre-existing pod carry pod association. With cgidmap enabled the
// cgroup-name association path is bypassed, so a matching event proves the
// cgroupfs fallback resolved the container. The metrics check confirms the
// cgfs resolver did the work.
func TestCgidmapCgroupfsFallback(t *testing.T) {
	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("cgidmap-fallback-exec").
			WithProcess(
				ec.NewProcessChecker().
					WithPod(ec.NewPodChecker().
						WithNamespace(sm.Full(namespace)).
						WithName(sm.Full(podName))).
					WithBinary(sm.Suffix("uname")),
			),
	)
	rpcChecker := checker.NewRPCChecker(execChecker, "cgidmapFallbackChecker").
		WithEventLimit(500).
		WithTimeLimit(2 * time.Minute)

	metricsChecker := metricschecker.NewMetricsChecker("cgidmapFallbackMetrics")

	runEventChecker := features.New("Check pod association").
		Assess("Exec events carry pod info", rpcChecker.CheckInNamespace(1*time.Minute, namespace)).
		Feature()

	checkMetrics := features.New("Check cgfs resolver metrics").
		Assess("Wait for event checker", rpcChecker.Wait(60*time.Second)).
		Assess("cgfs resolutions happened",
			metricsChecker.Greater("tetragon_cgfs_cgidmap_resolutions_total", 0)).
		Feature()

	runner.TestInParallel(t, runEventChecker, checkMetrics)
}
