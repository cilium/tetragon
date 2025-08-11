// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/operator/crd"
	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/cmdref"
)

func AddCommonFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.String(operatorOption.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(operatorOption.CMDRef)
	flags.Bool(operatorOption.SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions (CRDs) will not be created")
	flags.String(operatorOption.KubeCfgPath, "", "Kubeconfig filepath to connect to k8s")
	flags.String(operatorOption.ConfigDir, "", "Directory in which tetragon-operator-config configmap is mounted")
	flags.Bool(operatorOption.SkipPodInfoCRD, false, "When true, PodInfo Custom Resource Definition (CRD) will not be created")
	flags.Bool(operatorOption.SkipTracingPolicyCRD, false, "When true, TracingPolicy and TracingPolicyNamespaced Custom Resource Definition (CRD) will not be created")
	flags.Bool(operatorOption.ForceUpdateCRDs, false, "When true, operator will ignore current CRD version and forcefully update it")
}

func Initialize(cmd *cobra.Command) {
	// Populate option.Config with options from CLI.
	operatorOption.ConfigPopulate()
	cmdRefDir := viper.GetString(operatorOption.CMDRef)
	if cmdRefDir != "" {
		cmdref.GenMarkdown(cmd, cmdRefDir)
		os.Exit(0)
	}
	crd.RegisterCRDs()
}
