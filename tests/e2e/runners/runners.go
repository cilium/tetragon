// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package runners

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/cilium"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/state"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

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
	installCilium       env.Func
	installTetragon     env.Func
	uninstallTetragon   env.Func
	tetragonPortForward PortForwardFunc
	hasCalledInit       bool
	keepExportFiles     bool
	cancel              context.CancelFunc
	env.Environment
}

var DefaultRunner = Runner{
	setupCluster: func(testenv env.Environment) env.Func {
		return helpers.MaybeCreateTempKindCluster(testenv, ClusterPrefix)
	},
	installCilium: func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		client, err := c.NewClient()
		if err != nil {
			return ctx, err
		}
		// Only install Cilium if it does not already exist
		ciliumDs := &appsv1.DaemonSet{}
		if err := client.Resources("kube-system").Get(ctx, "cilium", "kube-system", ciliumDs); err != nil && apierrors.IsNotFound(err) {
			return cilium.Setup(cilium.WithNamespace("kube-system"), cilium.WithVersion(flags.Opts.CiliumVersion))(ctx, c)
		}
		return ctx, nil
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

func (r *Runner) WithInstallCiliumFn(install env.Func) *Runner {
	r.installCilium = install
	return r
}

func (r *Runner) WithInstallCilium(options ...cilium.Option) *Runner {
	r.installCilium = func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return cilium.Setup(options...)(ctx, cfg)
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
	r.Environment = r.Environment.WithContext(ctx)

	if r.setupCluster == nil {
		klog.Fatalf("Runner.setupCluster cannot be nil")
	}
	r.Setup(r.setupCluster(r.Environment))

	r.Setup(helpers.SetMinKernelVersion())

	if r.installCilium != nil && flags.Opts.InstallCilium {
		r.Setup(r.installCilium)
	}

	if r.installTetragon == nil {
		klog.Fatalf("Runner.installTetragon cannot be nil")
	}
	r.Setup(r.installTetragon)

	// Store test success or failure
	r.AfterEachTest(func(ctx context.Context, _ *envconf.Config, t *testing.T) (context.Context, error) {
		if t.Failed() {
			return context.WithValue(ctx, state.TestFailure, true), nil
		}
		return ctx, err
	})

	r.Finish(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		failure, ok := ctx.Value(state.TestFailure).(bool)
		if !ok {
			failure = false
		}
		ctx = context.WithValue(ctx, state.TestFailure, nil)
		// The test passed and we are not keeping export files, remove the export dir
		// and return early
		if !r.keepExportFiles && !failure {
			if exportDir, err := helpers.GetExportDir(ctx); err == nil {
				klog.Info("test passed and keep-export not set, removing export dir")
				if err := os.RemoveAll(exportDir); err != nil {
					klog.ErrorS(err, "failed to remove export dir")
				}
			}
			return ctx, err
		}
		return helpers.DumpInfo(ctx, c)
	})

	if r.tetragonPortForward != nil {
		r.Setup(r.tetragonPortForward(r.Environment))
	}

	if r.uninstallTetragon != nil {
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

// Must be called at the beinning of every test.
func (r *Runner) SetupExport(t *testing.T) {
	setup := features.New("Setup Export").Assess("Setup Export", func(ctx context.Context, _ *testing.T, _ *envconf.Config) context.Context {
		ctx, err := helpers.CreateExportDir(ctx, t)
		if err != nil {
			t.Fatalf("failed to create export dir: %s", err)
		}

		exportDir, err := helpers.GetExportDir(ctx)
		if err != nil {
			t.Fatalf("failed to get export dir: %s", err)
		}

		// Start the metrics and gops dumpers
		helpers.StartMetricsDumper(ctx, exportDir, 30*time.Second)
		helpers.StartGopsDumper(ctx, exportDir, 30*time.Second)

		return ctx
	}).Feature()

	r.Test(t, setup)
}
