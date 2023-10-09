// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/cmd/common"
	"github.com/cilium/tetragon/operator/cmd/serve"
	operatorOption "github.com/cilium/tetragon/operator/option"
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
			common.Initialize(cmd)
		},
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return viper.BindPFlags(cmd.Flags())
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

	common.AddCommonFlags(rootCmd)
	rootCmd.AddCommand(serve.New())
	return rootCmd
}
