// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
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

	// TetragonNamespace specifies the K8S namespace in which Tetragon is installed
	TetragonNamespace = "tetragon-namespace"

	// TetragonDaemonSetName specifies the Tetragon DaemonSet name
	TetragonDaemonSetName = "tetragon-daemon-set-name"

	// InstallTetragonDaemonSet specifies whether the Tetragon DaemonSet will be installed by operator
	InstallTetragonDaemonSet = "install-tetragon-daemon-set"

	// Default value for the TetragonNamespace config property
	namespaceDefaultValue = "kube-system"

	// Default value for the TetragonDaemonSetName config property
	daemonSetNameDefaultValue = "tetragon"
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

	// TetragonNamespace specifies the K8S namespace in which Tetragon is installed.
	TetragonNamespace string

	// TetragonDaemonSetName specifies the Tetragon DaemonSet name.
	TetragonDaemonSetName string

	// InstallTetragonDaemonSet enables installation of the Tetragon DaemonSet by operator.
	InstallTetragonDaemonSet bool
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
	Config.InstallTetragonDaemonSet = viper.GetBool(InstallTetragonDaemonSet)
	Config.TetragonNamespace = viper.GetString(TetragonNamespace)
	if Config.TetragonNamespace == "" {
		Config.TetragonNamespace = namespaceDefaultValue
	}
	Config.TetragonDaemonSetName = viper.GetString(TetragonDaemonSetName)
	if Config.TetragonDaemonSetName == "" {
		Config.TetragonDaemonSetName = daemonSetNameDefaultValue
	}
}
