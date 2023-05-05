// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd *cobra.Command
)

func main() {
	if err := New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func New() *cobra.Command {
	rootCmd = &cobra.Command{
		Use:   "tetra",
		Short: "Tetragon CLI",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if viper.GetBool(common.KeyDebug) {
				logger.DefaultLogger.SetLevel(logrus.DebugLevel)
			}
		},
	}

	addCommands(rootCmd)
	flags := rootCmd.PersistentFlags()
	flags.BoolP(common.KeyDebug, "d", false, "Enable debug messages")
	flags.String(common.KeyServerAddress, "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)
	return rootCmd
}
