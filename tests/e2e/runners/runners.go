// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package runners

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/cilium-e2e/pkg/e2ecluster/ciliuminstall"
	"github.com/cilium/cilium-e2e/pkg/e2ecluster/e2ehelpers"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install"
	"github.com/cilium/tetragon/tests/e2e/state"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	// Auth plugin for GCP
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

const (
	ClusterPrefix = "tetragon-ci"
)

type SetupClusterFunc func(env.Environment) env.Func
type PortForwardFunc func(env.Environment) env.Func

type Runner struct {
	setupCluster        SetupClusterFunc
	installCilium       env.Func
	installTetragon     env.Func
	tetragonPortForward PortForwardFunc
	hasCalledSetup      bool
	keepExportFiles     bool
}

var DefaultRunner = Runner{
	setupCluster: func(testenv env.Environment) env.Func {
		return e2ehelpers.MaybeCreateTempKindCluster(testenv, ClusterPrefix)
	},
	installCilium: func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		client, err := c.NewClient()
		if err != nil {
			return ctx, err
		}
		// Only install Cilium if it does not already exist
		ciliumDs := &appsv1.DaemonSet{}
		if err := client.Resources("kube-system").Get(ctx, "cilium", "kube-system", ciliumDs); err != nil && apierrors.IsNotFound(err) {
			return ciliuminstall.Setup(ciliuminstall.WithNamespace("kube-system"))(ctx, c)
		}
		return ctx, nil
	},
	installTetragon: install.Install(install.WithHelmOptions(map[string]string{
		"tetragon.exportAllowList": "",
	})),
	tetragonPortForward: func(testenv env.Environment) env.Func {
		return helpers.PortForwardTetragonPods(testenv)
	},
	hasCalledSetup:  false,
	keepExportFiles: false,
}

func NewRunner() *Runner {
	runner := DefaultRunner
	return &runner
}

func (r *Runner) WithKeepExportFiles(keep bool) *Runner {
	r.keepExportFiles = keep
	return r
}

func (r *Runner) WithSetupClusterFn(setup SetupClusterFunc) *Runner {
	r.setupCluster = setup
	return r
}

func (r *Runner) NoPortForward() *Runner {
	r.tetragonPortForward = func(_ env.Environment) env.Func {
		return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			klog.Info("Skipping Tetragon port forward")
			return ctx, nil
		}
	}
	return r
}

func (r *Runner) WithInstallTetragonFn(install env.Func) *Runner {
	r.installTetragon = install
	return r
}

func (r *Runner) WithInstallTetragon(options ...install.Option) *Runner {
	r.installTetragon = func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return install.Install(options...)(ctx, cfg)
	}
	return r
}

func (r *Runner) WithInstallCiliumFn(install env.Func) *Runner {
	r.installCilium = install
	return r
}

func (r *Runner) WithInstallCilium(options ...ciliuminstall.Option) *Runner {
	r.installCilium = func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return ciliuminstall.Setup(options...)(ctx, cfg)
	}
	return r
}

func (r *Runner) NoInstallCilium() *Runner {
	r.installCilium = func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		klog.Info("Skipping Cilium install")
		return ctx, nil
	}
	return r
}

func (r *Runner) Setup() env.Environment {
	if r.hasCalledSetup {
		klog.Fatalf("Cannot call Runner.Setup() twice")
	}
	r.hasCalledSetup = true

	cfg, err := envconf.NewFromFlags()
	if err != nil {
		klog.Fatalf("Failed to configure test environment: %w", err)
	}
	klog.Info("IMPORTANT: Tetragon e2e tests require parallel tests enabled. User preferences will be ignored.")
	cfg = cfg.WithParallelTestEnabled()

	klog.V(2).Infof("Command line flags: %+v", flags.Opts)
	r.keepExportFiles = flags.Opts.KeepExportData || r.keepExportFiles

	testenv := env.NewWithConfig(cfg)

	if r.setupCluster == nil {
		klog.Fatalf("Runner.setupCluster cannot be nil")
	}
	testenv.Setup(r.setupCluster(testenv))

	testenv.Setup(helpers.SetMinKernelVersion())

	if r.installCilium != nil && flags.Opts.InstallCilium {
		testenv.Setup(r.installCilium)
	}

	if r.installTetragon == nil {
		klog.Fatalf("Runner.installTetragon cannot be nil")
	}
	testenv.Setup(r.installTetragon)

	// Create the export dir before each test
	testenv.BeforeEachTest(func(ctx context.Context, cfg *envconf.Config, t *testing.T) (context.Context, error) {
		ctx, err := helpers.CreateExportDir(ctx, t)
		if err != nil {
			return ctx, fmt.Errorf("failed to create export dir: %w", err)
		}
		return ctx, nil
	})

	allTestsPassed := true

	// Dump info after each test
	testenv.AfterEachTest(func(ctx context.Context, c *envconf.Config, t *testing.T) (context.Context, error) {
		if t.Failed() {
			allTestsPassed = false
		}
		if t.Failed() || r.keepExportFiles {
			ctx, err = helpers.DumpInfo()(ctx, cfg, t)
		}
		return context.WithValue(ctx, state.Test, nil), err
	})

	testenv.Finish(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		// The test passed and we are not keeping export files, remove the export dir
		// and return early
		if !r.keepExportFiles && allTestsPassed {
			if exportDir, err := helpers.GetExportDir(ctx); err == nil {
				klog.Info("test passed and keep-export not set, removing export dir")
				if err := os.RemoveAll(exportDir); err != nil {
					klog.ErrorS(err, "failed to remove export dir")
				}
			}
			return context.WithValue(ctx, state.Test, nil), err
		}
		return context.WithValue(ctx, state.Test, nil), nil
	})

	if r.tetragonPortForward != nil {
		testenv.Setup(r.tetragonPortForward(testenv))
	}

	return testenv
}

func (r *Runner) Run(testenv env.Environment, m *testing.M) {
	os.Exit(testenv.Run(m))
}
