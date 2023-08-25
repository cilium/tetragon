// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

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
}

// Config represents the operator configuration.
var Config = &OperatorConfig{}
