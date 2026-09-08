// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package uprobe_ric_test e2e-tests uprobe resolvePathInContainer: the policy
// names a path that exists only inside the workload's image, and Tetragon must
// resolve it in each selected container and report the in-container path.
package uprobe_ric_test

import (
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/flags"
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
	// containerPath exists only inside the workload image, never in the
	// agent's mount namespace.
	containerPath = "/usr/bin/uprobe-simple"
)

// Manifests live in testdata/ so they can be inspected and applied manually.

//go:embed testdata/policy.yaml
var uprobePolicy string

//go:embed testdata/workload.yaml
var uprobeWorkload string

func TestMain(m *testing.M) {
	valuesFile, err := filepath.Abs("testdata/values.yaml")
	if err != nil {
		klog.Fatalf("failed to resolve values file: %v", err)
	}
	runner = runners.NewRunner().WithInstallTetragon(e2e.WithValuesFile(valuesFile)).Init()

	// The workload image is built locally, not published, so load it into kind.
	runner.Setup(helpers.LoadTesterProgsImage())

	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		klog.Infof("Deleting and recreating namespace %s", uprobeNamespace)
		ctx, _ = helpers.DeleteNamespace(uprobeNamespace, true)(ctx, c)
		ctx, err := helpers.CreateNamespace(uprobeNamespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}
		return ctx, nil
	})

	// The workload namespace and the cluster-scoped policy outlive the run
	// otherwise; a leftover policy also fails the next run's install.
	runner.Finish(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.UnloadCRDString("", uprobePolicy, false)(ctx, c)
		ctx, _ = helpers.DeleteNamespace(uprobeNamespace, false)(ctx, c)
		return ctx, nil
	})

	runner.Run(m)
}

func TestUprobeResolvePathInContainer(t *testing.T) {
	// The event must report the in-container path, not the agent-side handle
	// the uprobe was attached through.
	uprobeChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessUprobeChecker("uprobe-ric-pizza").
			WithPath(sm.Full(containerPath)).
			WithSymbol(sm.Full("pizza")).
			WithProcess(ec.NewProcessChecker().
				WithPod(ec.NewPodChecker().WithNamespace(sm.Full(uprobeNamespace)))),
	)
	rc := checker.NewRPCChecker(uprobeChecker, "uprobe-ric-checker").
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

	runWorkload := features.New("uprobe resolvePathInContainer").
		// Policy before workload: containers are attached as pod events
		// arrive, and those running at load are claimed from the informer.
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
			objs, err := decoder.DecodeAll(ctx, strings.NewReader(uprobeWorkload),
				decoder.MutateOption(setTesterProgsImage))
			if err == nil {
				ctx, err = helpers.LoadObjects(uprobeNamespace, objs, true)(ctx, c)
			}
			if err != nil {
				klog.ErrorS(err, "failed to start workload")
				t.Fail()
			}
			return ctx
		}).
		Feature()

	runner.TestInParallel(t, runWorkload, runEventChecker)
}

// setTesterProgsImage overrides the workload image from the test flags.
func setTesterProgsImage(obj k8s.Object) error {
	d, ok := obj.(*appsv1.Deployment)
	if !ok {
		return fmt.Errorf("unexpected workload object %T", obj)
	}
	for i := range d.Spec.Template.Spec.Containers {
		d.Spec.Template.Spec.Containers[i].Image = flags.Opts.TesterProgsImage
	}
	return nil
}
