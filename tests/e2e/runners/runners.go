// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package runners

import (
	"context"
	"os"
	"testing"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"

	// Auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	ClusterPrefix = "tetragon-ci"
)

type SetupClusterFunc func(env.Environment) env.Func
type PortForwardFunc func(env.Environment) env.Func

type Runner struct {
	setupCluster        SetupClusterFunc
	installTetragon     env.Func
	uninstallTetragon   env.Func
	tetragonPortForward PortForwardFunc
	hasCalledInit       bool
	keepExportFiles     bool
	cancel              context.CancelFunc
	setupTetragonFailed bool
	env.Environment
}

var DefaultRunner = Runner{
	setupCluster: func(testenv env.Environment) env.Func {
		return helpers.MaybeCreateTempKindCluster(testenv, ClusterPrefix)
	},
	installTetragon: tetragon.Install(tetragon.WithHelmOptions(map[string]string{
		"tetragon.exportAllowList":    "",
		"tetragon.enablePolicyFilter": "true",
	})),
	uninstallTetragon: tetragon.Uninstall(tetragon.WithHelmOptions(map[string]string{})),
	tetragonPortForward: func(testenv env.Environment) env.Func {
		return helpers.PortForwardTetragonPods(testenv)
	},
	hasCalledInit:   false,
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

func (r *Runner) WithInstallTetragon(options ...tetragon.Option) *Runner {
	r.installTetragon = func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return tetragon.Install(options...)(ctx, cfg)
	}
	return r
}

// Initialize the configured runner. Must be called exactly once.
func (r *Runner) Init() *Runner {
	if r.hasCalledInit {
		klog.Fatalf("Cannot call Runner.Init() twice")
	}
	r.hasCalledInit = true

	config := textlogger.NewConfig(
		textlogger.Verbosity(4), // Matches Kubernetes "debug" level.
		textlogger.Output(os.Stdout),
	)
	log.SetLogger(textlogger.NewLogger(config))

	cfg, err := envconf.NewFromFlags()
	if err != nil {
		klog.Fatalf("Failed to configure test environment")
	}
	klog.Info("IMPORTANT: Tetragon e2e tests require parallel tests enabled. User preferences will be ignored.")
	cfg = cfg.WithParallelTestEnabled()

	klog.V(2).Infof("Command line flags: %+v", flags.Opts)
	r.keepExportFiles = flags.Opts.KeepExportData || r.keepExportFiles

	r.Environment = env.NewWithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.Environment = r.WithContext(ctx)

	if r.setupCluster == nil {
		klog.Fatalf("Runner.setupCluster cannot be nil")
	}
	r.Setup(r.setupCluster(r.Environment))

	r.Setup(helpers.SetMinKernelVersion())

	if r.installTetragon == nil {
		klog.Fatalf("Runner.installTetragon cannot be nil")
	}
	r.Setup(func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		ctx, err := r.installTetragon(ctx, config)
		if err != nil {
			r.setupTetragonFailed = true
		}
		return ctx, err
	})

	r.BeforeEachTest(func(ctx context.Context, _ *envconf.Config, t *testing.T) (context.Context, error) {
		return r.SetupExport(ctx, t)
	})

	r.AfterEachTest(func(ctx context.Context, c *envconf.Config, t *testing.T) (context.Context, error) {
		if t.Failed() {
			return helpers.DumpInfo(ctx, c)
		}
		if r.keepExportFiles {
			return ctx, nil
		}
		exportDir, err := helpers.GetExportDir(ctx)
		if err != nil {
			return ctx, err
		}
		klog.InfoS("test passed and keep-export not set, removing export dir", "dir", exportDir)
		if err := os.RemoveAll(exportDir); err != nil {
			return ctx, err
		}
		return ctx, nil
	})

	if r.tetragonPortForward != nil {
		r.Setup(func(ctx context.Context, config *envconf.Config) (context.Context, error) {
			ctx, err := r.tetragonPortForward(r.Environment)(ctx, config)
			if err != nil {
				r.setupTetragonFailed = true
			}
			return ctx, err
		})
	}

	r.Finish(func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		if !r.setupTetragonFailed {
			return ctx, nil
		}
		ctx, err := helpers.CreateExportDir(ctx, "setup")
		if err != nil {
			return ctx, err
		}
		return helpers.DumpInfo(ctx, config)
	})

	if r.uninstallTetragon != nil && flags.Opts.UninstallTetragon {
		r.Finish(r.uninstallTetragon)
	}

	return r
}

// Run the tests. Exits with a corresponding status code. Must be called at the end of
// TestMain().
func (r *Runner) Run(m *testing.M) {
	if !r.hasCalledInit {
		klog.Fatal("runner.Init() must be called")
	}
	defer r.cancelContext()
	os.Exit(r.Environment.Run(m))
}

func (r *Runner) cancelContext() {
	if r.cancel != nil {
		r.cancel()
	} else {
		klog.Warning("r.cancel() is nil, refusing to cancel context")
	}
}

func (r *Runner) SetupExport(ctx context.Context, t *testing.T) (context.Context, error) {
	ctx, err := helpers.CreateExportDir(ctx, t.Name())
	if err != nil {
		return ctx, err
	}

	exportDir, err := helpers.GetExportDir(ctx)
	if err != nil {
		return ctx, err
	}

	// Start the metrics and gops dumpers
	helpers.StartMetricsDumper(ctx, exportDir, 30*time.Second)
	helpers.StartGopsDumper(ctx, exportDir, 30*time.Second)
	return ctx, nil
}
