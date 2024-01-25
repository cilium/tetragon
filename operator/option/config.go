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

	// ForceUpdateCRDs specifies whether operator should ignore current CRD version
	// and forcefully update it.
	ForceUpdateCRDs = "force-update-crds"
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
}
