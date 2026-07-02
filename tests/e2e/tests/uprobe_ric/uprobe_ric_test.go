// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package uprobe_ric_test e2e-tests the uprobe resolvePathInContainer feature over
// the runtime-hook (rthook) path: with CRI disabled, a container's root is
// resolved only from the CreateContainer hook's RootDir cache. The policy is
// loaded before the workload, and process_uprobe events must report the
// in-container path.
package uprobe_ric_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	e2e "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

// runner holds the test environment from runners.NewRunner().Init().
var runner *runners.Runner

const (
	uprobeNamespace = "uprobe-ric"
	policyName      = "uprobe-ric"
	uprobeSymbol    = "pizza"
	// In-container path; the event must report this, not the attach fd handle.
	uprobePath = "/usr/bin/uprobe-simple"
)

func TestMain(m *testing.M) {
	// rthook values: CRI off, nri-hook, fail-open. Image overrides come from
	// -tetragon.helm.set and are preserved.
	valuesFile, err := filepath.Abs("testdata/values.yaml")
	if err != nil {
		klog.Fatalf("failed to resolve values file: %v", err)
	}
	runner = runners.NewRunner().WithInstallTetragon(e2e.WithValuesFile(valuesFile)).Init()

	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		klog.Infof("Deleting and recreating namespace %s", uprobeNamespace)
		ctx, _ = helpers.DeleteNamespace(uprobeNamespace, true)(ctx, c)
		ctx, err := helpers.CreateNamespace(uprobeNamespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}
		return ctx, nil
	})

	runner.Run(m)
}

func TestUprobeResolvePathInContainer(t *testing.T) {
	uc := &uprobeChecker{}
	rc := checker.NewRPCChecker(uc, "uprobe-ric-checker").
		WithEventLimit(1000).
		WithTimeLimit(90 * time.Second)

	runEventChecker := features.New("Run uprobe event checks").
		Assess("Run uprobe event checks", rc.CheckWithFilters(
			90*time.Second,
			// allow list: process_uprobe in our namespace
			[]*tetragon.Filter{{
				EventSet:  []tetragon.EventType{tetragon.EventType_PROCESS_UPROBE},
				Namespace: []string{uprobeNamespace},
			}},
			// deny list
			[]*tetragon.Filter{},
		)).Feature()

	runWorkload := features.New("uprobe resolvePathInContainer via runtime hook").
		// Policy before workload: with CRI off, the container is discovered via
		// the pod-event seam only after the policy is loaded.
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString("", uprobePolicy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to install policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for policy", func(ctx context.Context, _ *testing.T, _ *envconf.Config) context.Context {
			if err := grpc.WaitForTracingPolicy(ctx, policyName); err != nil {
				klog.ErrorS(err, "failed to wait for policy")
				t.Fail()
			}
			return ctx
		}).
		Assess("Wait for Checker", rc.Wait(30*time.Second)).
		Assess("Start workload", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(uprobeNamespace, uprobeWorkload, true)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to start workload")
				t.Fail()
			}
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, runWorkload, runEventChecker)
}

// uprobeChecker passes on the first process_uprobe matching the expected symbol,
// in-container path and pod namespace; FinalCheck fails if none arrive in time.
type uprobeChecker struct {
	matches int
}

func (c *uprobeChecker) NextEventCheck(event ec.Event, _ *slog.Logger) (bool, error) {
	ev, ok := event.(*tetragon.ProcessUprobe)
	if !ok {
		return false, errors.New("not a process_uprobe event")
	}
	if sym := ev.GetSymbol(); sym != uprobeSymbol {
		return false, fmt.Errorf("unexpected symbol %q", sym)
	}
	if path := ev.GetPath(); path != uprobePath {
		return false, fmt.Errorf("unexpected path %q (want in-container path %q)", path, uprobePath)
	}
	if ns := ev.GetProcess().GetPod().GetNamespace(); ns != uprobeNamespace {
		return false, fmt.Errorf("unexpected namespace %q", ns)
	}
	c.matches++
	// One match proves the per-container uprobe attached.
	return true, nil
}

func (c *uprobeChecker) FinalCheck(_ *slog.Logger) error {
	if c.matches > 0 {
		return nil
	}
	return fmt.Errorf("no process_uprobe events for symbol %q at %q in namespace %q", uprobeSymbol, uprobePath, uprobeNamespace)
}

const uprobePolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-ric"
spec:
  podSelector:
    matchLabels:
      app: uprobe-ric
  uprobes:
  - path: "/usr/bin/uprobe-simple"
    symbols:
    - "pizza"
    resolvePathInContainer: true
`

const uprobeWorkload = `
kind: Deployment
apiVersion: apps/v1
metadata:
  name: uprobe-ric
spec:
  replicas: 1
  selector:
    matchLabels:
      app: uprobe-ric
  template:
    metadata:
      labels:
        app: uprobe-ric
    spec:
      containers:
      - name: uprobe-ric
        image: docker.io/sayboras/tetragon-e2e-uprobe-ric:test
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", "while true; do /usr/bin/uprobe-simple >/dev/null 2>&1; sleep 0.5; done"]
`
