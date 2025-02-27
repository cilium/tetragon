// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package serve

import (
	"fmt"
	"time"

	"github.com/bombsimon/logrusr/v4"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/cmd/common"
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

const (
	// LeaderElectionID is the name of the leader election Lease resource
	LeaderElectionID = "tetragon-operator-resource-lock"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumiov1alpha1.AddToScheme(scheme))
}

func validateLeaderElectionParams() error {
	if operatorOption.Config.LeaderElectionLeaseDuration <= operatorOption.Config.LeaderElectionRenewDeadline {
		return fmt.Errorf("leader-election-lease-duration must be greater than leader-election-renew-deadline")
	}
	if operatorOption.Config.LeaderElectionRenewDeadline <= operatorOption.Config.LeaderElectionRetryPeriod {
		return fmt.Errorf("leader-election-renew-deadline must be greater than leader-election-retry-period")
	}
	return nil
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "serve",
		Short: "Run Tetragon operator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := logrusr.New(logging.DefaultLogger.WithField(logfields.LogSubsys, "operator"))
			ctrl.SetLogger(log)
			common.Initialize(cmd)
			if err := validateLeaderElectionParams(); err != nil {
				return fmt.Errorf("invalid leader election parameters: %w", err)
			}
			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                        scheme,
				Metrics:                       metricsserver.Options{BindAddress: operatorOption.Config.MetricsAddr},
				WebhookServer:                 webhook.NewServer(webhook.Options{Port: 9443}),
				HealthProbeBindAddress:        operatorOption.Config.ProbeAddr,
				LeaderElection:                operatorOption.Config.EnableLeaderElection,
				LeaderElectionID:              LeaderElectionID,
				LeaderElectionNamespace:       operatorOption.Config.LeaderElectionNamespace,
				LeaderElectionReleaseOnCancel: true,
				LeaseDuration:                 &operatorOption.Config.LeaderElectionLeaseDuration,
				RenewDeadline:                 &operatorOption.Config.LeaderElectionRenewDeadline,
				RetryPeriod:                   &operatorOption.Config.LeaderElectionRetryPeriod,
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

			setupLog.Info("starting manager", "metricsAddr", operatorOption.Config.MetricsAddr, "probeAddr", operatorOption.Config.ProbeAddr, "leaderElection", operatorOption.Config.EnableLeaderElection)
			if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
				return fmt.Errorf("problem running manager %w", err)
			}
			setupLog.Info("manager stopped gracefully")
			return nil
		},
	}
	common.AddCommonFlags(&cmd)
	cmd.Flags().StringVar(&operatorOption.Config.MetricsAddr, "metrics-bind-address", "0", "The address the metric endpoint binds to.")
	cmd.Flags().StringVar(&operatorOption.Config.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&operatorOption.Config.EnableLeaderElection, "leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().StringVar(&operatorOption.Config.LeaderElectionNamespace, "leader-election-namespace", "",
		"Kubernetes namespace in which the leader election Lease resource should be created.")
	cmd.Flags().DurationVar(&operatorOption.Config.LeaderElectionLeaseDuration, "leader-election-lease-duration", 15*time.Second,
		"Duration that non-leader operator candidates will wait before forcing to acquire leadership")
	cmd.Flags().DurationVar(&operatorOption.Config.LeaderElectionRenewDeadline, "leader-election-renew-deadline", 5*time.Second,
		"Duration that current acting master will retry refreshing leadership in before giving up the lock")
	cmd.Flags().DurationVar(&operatorOption.Config.LeaderElectionRetryPeriod, "leader-election-retry-period", 2*time.Second,
		"Duration that LeaderElector clients should wait between retries of the actions")
	viper.BindPFlags(cmd.Flags())
	return &cmd
}
