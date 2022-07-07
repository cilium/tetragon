// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package install

import (
	"context"
	"fmt"
	"strings"

	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"github.com/cilium/cilium-e2e/pkg/e2ecluster/e2ehelpers"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/state"
)

var (
	AgentImageKey    = "tetragon.image.override"
	OperatorImageKey = "tetragonOperator.image.override"
)

type Option func(*flags.HelmOptions)

func WithNoWait() Option {
	return func(o *flags.HelmOptions) { o.Wait = false }
}

func WithDaemonSetName(name string) Option {
	return func(o *flags.HelmOptions) { o.DaemonSetName = name }
}

func WithHelmChart(chart string) Option {
	return func(o *flags.HelmOptions) { o.HelmChart = chart }
}

func WithHelmChartVersion(version string) Option {
	return func(o *flags.HelmOptions) { o.HelmChartVersion = version }
}

func WithNamespace(namespace string) Option {
	return func(o *flags.HelmOptions) { o.Namespace = namespace }
}

func WithValuesFile(file string) Option {
	return func(o *flags.HelmOptions) { o.ValuesFile = file }
}

func WithHelmOptions(options map[string]string) Option {
	return func(o *flags.HelmOptions) {
		if o.HelmValues == nil {
			o.HelmValues = make(map[string]string)
		}
		for k, v := range options {
			o.HelmValues[k] = v
		}
	}
}

func WithReplaceHelmOptions(options map[string]string) Option {
	return func(o *flags.HelmOptions) { o.HelmValues = options }
}

func processOpts(opts ...Option) *flags.HelmOptions {
	defaultOpts := flags.Opts.Helm
	for _, opt := range opts {
		opt(&defaultOpts)
	}
	return &defaultOpts
}

func Install(opts ...Option) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		o := processOpts(opts...)
		klog.InfoS("Installing Tetragon...", "opts", o)

		manager := helm.New(cfg.KubeconfigFile())

		// Only add and upate repo if helm url is specified
		if o.HelmRepoUrl != "" {
			repoName := strings.Split(o.HelmChart, "/")[0]
			if err := manager.RunRepo(helm.WithArgs("add", repoName, o.HelmRepoUrl)); err != nil {
				return ctx, fmt.Errorf("failed to add helm repo %s (%s): %w", repoName, o.HelmRepoUrl, err)
			}

			if err := manager.RunRepo(helm.WithArgs("update")); err != nil {
				return ctx, fmt.Errorf("failed to update helm repo: %w", err)
			}
		}

		var helmArgs strings.Builder
		for k, v := range o.HelmValues {
			helmArgs.WriteString(fmt.Sprintf(" --set=%s=%s", k, v))
			if clusterName := e2ehelpers.GetTempKindClusterName(ctx); clusterName != "" {
				switch k {
				case AgentImageKey:
					fallthrough
				case OperatorImageKey:
					klog.InfoS("Loading image into kind cluster", "cluster", clusterName, "image", v, "helm", k)
					var err error
					if ctx, err = envfuncs.LoadDockerImageToCluster(clusterName, v)(ctx, cfg); err != nil {
						// If the image is not present locally, don't worry about it but
						// log a message
						if strings.Contains(err.Error(), "not present locally") {
							klog.InfoS("Image is not present locally, attempting to install Tetragon regardless", "cluster", clusterName, "image", v, "helm", k)
							break
						}
						return ctx, fmt.Errorf("failed to load image %s into cluster %s: %w", v, clusterName, err)
					}
				}
			}
		}
		if o.ValuesFile != "" {
			helmArgs.WriteString(fmt.Sprintf(" --values=%s", o.ValuesFile))
		}
		helmArgs.WriteString(" --install")

		helmOpts := []helm.Option{
			helm.WithName(o.DaemonSetName),
			helm.WithNamespace(o.Namespace),
			helm.WithChart(o.HelmChart),
			helm.WithVersion(o.HelmChartVersion),
			helm.WithArgs(helmArgs.String()),
		}

		if err := manager.RunUpgrade(helmOpts...); err != nil {
			return ctx, fmt.Errorf("failed to install via helm chart: %w", err)
		}

		if o.Wait {
			client, err := cfg.NewClient()
			if err != nil {
				return ctx, err
			}
			r := client.Resources(o.Namespace)

			ds := v1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      o.DaemonSetName,
					Namespace: o.Namespace,
				},
			}

			// Wait for Tetragon daemon set to be ready
			klog.Info("Waiting for Tetragon DaemonSet to be ready...")
			wait.For(conditions.New(r).ResourceMatch(&ds, func(object k8s.Object) bool {
				o := object.(*v1.DaemonSet)
				return o.Status.NumberReady == o.Status.DesiredNumberScheduled
			}))
			klog.Info("Tetragon DaemonSet is ready!")
		}

		return context.WithValue(ctx, state.InstallOpts, o), nil
	}
}
