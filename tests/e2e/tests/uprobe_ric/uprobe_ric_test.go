// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package uprobe_ric_test e2e-tests uprobe resolvePathInContainer over the
// rthook path: with CRI off, CreateContainer hook records authorize container
// root resolution through the standard host proc mount.
package uprobe_ric_test

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
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
)

// expectedUprobes maps each symbol to the in-container path the event must
// report (not the attach fd handle).
var expectedUprobes = map[string]string{
	"pizza":  "/usr/bin/uprobe-simple",
	"burger": "/usr/bin/uprobe-simple",
}

// Manifests live in testdata/ so they can be inspected and applied manually.

//go:embed testdata/policy.yaml
var uprobePolicy string

//go:embed testdata/workload.yaml
var uprobeWorkload string

func TestMain(m *testing.M) {
	// rthook values: CRI off, nri-hook, fail-open.
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

	runner.Run(m)
}

func TestUprobeResolvePathInContainer(t *testing.T) {
	uc := &uprobeChecker{seen: map[string]struct{}{}}
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
		// Policy before workload: with CRI off, containers are only
		// discovered via pod events after the policy is loaded.
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			// Pin the exact in-container binary via binaryDigests. A passing
			// uprobe assertion then also proves per-container digest
			// verification: a mismatch would attach nothing.
			digest, err := helpers.TesterProgsBinaryDigest(ctx, flags.Opts.TesterProgsImage, "/usr/bin/uprobe-simple")
			if err != nil {
				klog.ErrorS(err, "failed to compute tester-progs binary digest")
				t.Fail()
				return ctx
			}
			policy, err := renderPolicy(uprobePolicy, digest)
			if err != nil {
				klog.ErrorS(err, "failed to render policy")
				t.Fail()
				return ctx
			}
			ctx, err = helpers.LoadCRDString("", policy, false)(ctx, c)
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

// uprobeChecker matches process_uprobe events against expectedUprobes;
// FinalCheck fails unless every expected symbol was seen.
type uprobeChecker struct {
	seen map[string]struct{}
}

func (c *uprobeChecker) NextEventCheck(event ec.Event, _ *slog.Logger) (bool, error) {
	ev, ok := event.(*tetragon.ProcessUprobe)
	if !ok {
		return false, errors.New("not a process_uprobe event")
	}
	sym := ev.GetSymbol()
	wantPath, ok := expectedUprobes[sym]
	if !ok {
		return false, fmt.Errorf("unexpected symbol %q", sym)
	}
	if path := ev.GetPath(); path != wantPath {
		return false, fmt.Errorf("symbol %q: unexpected path %q (want in-container path %q)", sym, path, wantPath)
	}
	if ns := ev.GetProcess().GetPod().GetNamespace(); ns != uprobeNamespace {
		return false, fmt.Errorf("unexpected namespace %q", ns)
	}
	c.seen[sym] = struct{}{}
	// done once every expected symbol was observed.
	return len(c.seen) == len(expectedUprobes), nil
}

func (c *uprobeChecker) FinalCheck(_ *slog.Logger) error {
	var missing []string
	for sym := range expectedUprobes {
		if _, ok := c.seen[sym]; !ok {
			missing = append(missing, sym)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("no process_uprobe events for symbols %v in namespace %q", missing, uprobeNamespace)
}

// renderPolicy fills the policy template's binaryDigests placeholder with the
// resolved in-container binary digest.
func renderPolicy(tmplStr, digest string) (string, error) {
	tmpl, err := template.New("policy").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parsing policy template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ Digest string }{Digest: digest}); err != nil {
		return "", fmt.Errorf("rendering policy template: %w", err)
	}
	return buf.String(), nil
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
