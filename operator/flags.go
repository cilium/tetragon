// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"strings"

	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	initializeFlags()
}

func initializeFlags() {
	cobra.OnInitialize(func() {
		replacer := strings.NewReplacer("-", "_", ".", "_")
		viper.SetEnvKeyReplacer(replacer)
		viper.SetEnvPrefix(operatorOption.TetragonOpEnvPrefix)
		viper.AutomaticEnv()
		configDir := viper.GetString(operatorOption.ConfigDir)
		if configDir != "" {
			err := option.ReadConfigDir(configDir)
			if err != nil {
				log.WithField(operatorOption.ConfigDir, configDir).WithError(err).Fatal("Failed to read config from directory")
			} else {
				log.WithField(operatorOption.ConfigDir, configDir).Info("Loaded config from directory")
			}
		}
	})

	flags := rootCmd.Flags()

	flags.String(operatorOption.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(operatorOption.CMDRef)

	flags.Bool(operatorOption.SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions (CRDs) will not be created")

	flags.String(operatorOption.KubeCfgPath, "", "Kubeconfig filepath to connect to k8s")

	flags.String(operatorOption.ConfigDir, "", "Directory in which tetragon-operator-config configmap is mounted")

	viper.BindPFlags(flags)
}

// Populate sets all options with the values from viper.
func configPopulate() {
	operatorOption.Config.SkipCRDCreation = viper.GetBool(operatorOption.SkipCRDCreation)
	operatorOption.Config.KubeCfgPath = viper.GetString(operatorOption.KubeCfgPath)
	operatorOption.Config.ConfigDir = viper.GetString(operatorOption.ConfigDir)
}
