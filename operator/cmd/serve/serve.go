// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package serve

import (
	"fmt"

	"github.com/bombsimon/logrusr/v4"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/cmd/common"
	"github.com/cilium/tetragon/operator/daemon"
	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/operator/podinfo"
	ciliumiov1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	metricsAddr          string
	enableLeaderElection bool
	probeAddr            string
	scheme               = runtime.NewScheme()
	setupLog             = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumiov1alpha1.AddToScheme(scheme))
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "serve",
		Short: "Run Tetragon operator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := logrusr.New(logging.DefaultLogger.WithField(logfields.LogSubsys, "operator"))
			ctrl.SetLogger(log)
			common.Initialize(cmd)

			if operatorOption.Config.InstallTetragonDaemonSet {
				if err := daemon.InstallTetragonDaemonSet(); err != nil {
					return fmt.Errorf("unable to install tetragon daemon set: %w", err)
				}
			}

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                 scheme,
				Metrics:                metricsserver.Options{BindAddress: metricsAddr},
				WebhookServer:          webhook.NewServer(webhook.Options{Port: 9443}),
				HealthProbeBindAddress: probeAddr,
				LeaderElection:         enableLeaderElection,
				LeaderElectionID:       "f161f714.tetragon.cilium.io",
				// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
				// when the Manager ends. This requires the binary to immediately end when the
				// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
				// speeds up voluntary leader transitions as the new leader don't have to wait
				// LeaseDuration time first.
				//
				// In the default scaffold provided, the program ends immediately after
				// the manager stops, so would be fine to enable this option. However,
				// if you are doing or is intended to do any operation such as perform cleanups
				// after the manager stops then its usage might be unsafe.
				// LeaderElectionReleaseOnCancel: true,
			})
			if err != nil {
				return fmt.Errorf("unable to start manager: %w", err)
			}

			if !operatorOption.Config.SkipPodInfoCRD {
				if err = (&podinfo.Reconciler{
					Client: mgr.GetClient(),
				}).SetupWithManager(mgr); err != nil {
					return fmt.Errorf("unable to create controller: %w %s %s", err, "controller", "podinfo")
				}
			}

			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				return fmt.Errorf("unable to set up health check %w", err)
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				return fmt.Errorf("unable to set up ready check %w", err)
			}

			setupLog.Info("starting manager")
			if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
				return fmt.Errorf("problem running manager %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":2113", "The address the metric endpoint binds to.")
	cmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	common.AddCommonFlags(&cmd)
	_ = viper.BindPFlags(cmd.Flags())
	return &cmd
}
