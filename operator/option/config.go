// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"time"

	"github.com/spf13/viper"
)

const (
	TetragonOpEnvPrefix = "TETRAGON_OPERATOR"

	// SkipCRDCreation specifies whether the CustomResourceDefinition will be
	// disabled for the operator
	SkipCRDCreation = "skip-crd-creation"

	// CMDRef is the path to cmdref output directory
	CMDRef = "cmdref"

	// KubeCfgPath is the path to a kubeconfig file
	KubeCfgPath = "kube-config"

	// ConfigDir specifies the directory in which tetragon-operator-config configmap is mounted.
	ConfigDir = "config-dir"

	// SkipPodInfoCRD specifies whether the tetragonPod CustomResourceDefinition will be
	// disabled
	SkipPodInfoCRD = "skip-pod-info-crd"

	// SkipTracingPolicyCRD specifies whether the tracing-policies CustomResourceDefinition will be
	// disabled
	SkipTracingPolicyCRD = "skip-tracing-policy-crd"

	// ForceUpdateCRDs specifies whether operator should ignore current CRD version
	// and forcefully update it.
	ForceUpdateCRDs = "force-update-crds"

	// MetricsAddr is the address the metric endpoint binds to.
	MetricsAddr = "metrics-bind-address"

	// ProbeAddr is the address the probe endpoint binds to.
	ProbeAddr = "health-probe-bind-address"

	// EnableLeaderElection enables leader election for controller manager.
	EnableLeaderElection = "leader-election"

	// LeaderElectionNamespace is the Kubernetes namespace in which the leader election Lease resource should be created.
	LeaderElectionNamespace = "leader-election-namespace"

	// LeaderElectionLeaseDuration is the duration that non-leader operator candidates will wait before forcing to acquire leadership.
	LeaderElectionLeaseDuration = "leader-election-lease-duration"

	// LeaderElectionRenewDeadline is the duration that current acting master will retry refreshing leadership in before giving up the lock.
	LeaderElectionRenewDeadline = "leader-election-renew-deadline"

	// LeaderElectionRetryPeriod is the duration that LeaderElector clients should wait between retries of the actions.
	LeaderElectionRetryPeriod = "leader-election-retry-period"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// SkipCRDCreation disables creation of the CustomResourceDefinition
	// for the operator
	SkipCRDCreation bool

	// KubeCfgPath allows users to specify a kubeconfig file to be used by the operator
	KubeCfgPath string

	// ConfigDir specifies the directory in which tetragon-operator-config configmap is mounted.
	ConfigDir string

	// SkipPodInfoCRD disables creation of the TetragonPod CustomResourceDefinition only.
	SkipPodInfoCRD bool

	// SkipTracingPolicyCRD disables creation of the TracingPolicy and
	// TracingPolicyNamespaced CustomResourceDefinition only.
	SkipTracingPolicyCRD bool

	// ForceUpdateCRDs forces the CRD to be updated even if it's version
	// is lower than the one in the cluster.
	ForceUpdateCRDs bool

	// MetricsAddr is the address the metric endpoint binds to.
	MetricsAddr string

	// ProbeAddr is the address the probe endpoint binds to.
	ProbeAddr string

	// EnableLeaderElection enables leader election for controller manager.
	EnableLeaderElection bool

	// LeaderElectionNamespace is the Kubernetes namespace in which the leader election Lease resource should be created.
	LeaderElectionNamespace string

	// LeaderElectionLeaseDuration is the duration that non-leader operator candidates will wait before forcing to acquire leadership.
	LeaderElectionLeaseDuration time.Duration

	// LeaderElectionRenewDeadline is the duration that current acting master will retry refreshing leadership in before giving up the lock.
	LeaderElectionRenewDeadline time.Duration

	// LeaderElectionRetryPeriod is the duration that LeaderElector clients should wait between retries of the actions.
	LeaderElectionRetryPeriod time.Duration
}

// Config represents the operator configuration.
var Config = &OperatorConfig{}

// ConfigPopulate sets all options with the values from viper.
func ConfigPopulate() {
	Config.SkipCRDCreation = viper.GetBool(SkipCRDCreation)
	Config.KubeCfgPath = viper.GetString(KubeCfgPath)
	Config.ConfigDir = viper.GetString(ConfigDir)
	Config.SkipPodInfoCRD = viper.GetBool(SkipPodInfoCRD)
	Config.SkipTracingPolicyCRD = viper.GetBool(SkipTracingPolicyCRD)
	Config.ForceUpdateCRDs = viper.GetBool(ForceUpdateCRDs)
	Config.MetricsAddr = viper.GetString(MetricsAddr)
	Config.ProbeAddr = viper.GetString(ProbeAddr)
	Config.EnableLeaderElection = viper.GetBool(EnableLeaderElection)
	Config.LeaderElectionNamespace = viper.GetString(LeaderElectionNamespace)
	Config.LeaderElectionLeaseDuration = viper.GetDuration(LeaderElectionLeaseDuration)
	Config.LeaderElectionRenewDeadline = viper.GetDuration(LeaderElectionRenewDeadline)
	Config.LeaderElectionRetryPeriod = viper.GetDuration(LeaderElectionRetryPeriod)
}
