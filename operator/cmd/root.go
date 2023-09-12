// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/crd"
	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/cmdref"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// New create a new root command.
func New() *cobra.Command {
	binaryName := filepath.Base(os.Args[0])
	log := logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, args []string) {
			// Populate option.Config with options from CLI.
			operatorOption.ConfigPopulate()
			cmdRefDir := viper.GetString(operatorOption.CMDRef)
			if cmdRefDir != "" {
				cmdref.GenMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}
			crd.RegisterCRDs()
		},
	}

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

	flags.Bool(operatorOption.SkipPodInfoCRD, false, "When true, PodInfo Custom Resource Definition (CRD) will not be created")

	viper.BindPFlags(flags)

	return rootCmd
}
