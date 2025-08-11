// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/operator/cmd/common"
	"github.com/cilium/tetragon/operator/cmd/serve"
	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
)

// New create a new root command.
func New() *cobra.Command {
	binaryName := filepath.Base(os.Args[0])
	log := logger.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)

	rootCmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, _ []string) {
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
				log.With(operatorOption.ConfigDir, configDir, logfields.Error, err).Error("Failed to read config from directory")
				os.Exit(1)
			}
			log.With(operatorOption.ConfigDir, configDir).Info("Loaded config from directory")
		}
	})

	common.AddCommonFlags(rootCmd)
	rootCmd.AddCommand(serve.New())
	return rootCmd
}
