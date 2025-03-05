// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"os"
	"time"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	rootCmd *cobra.Command
)

func main() {
	if err := New().Execute(); err != nil {
		os.Exit(1)
	}
}

func New() *cobra.Command {
	rootCmd = &cobra.Command{
		Use:          "tetra",
		Short:        "Tetragon CLI",
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if common.Debug {
				logger.DefaultLogger.SetLevel(logrus.DebugLevel)
			}
		},
	}
	// by default, it fallbacks to stderr
	rootCmd.SetOut(os.Stdout)

	addCommands(rootCmd)
	flags := rootCmd.PersistentFlags()
	flags.BoolVarP(&common.Debug, common.KeyDebug, "d", false, "Enable debug messages")
	flags.StringVar(&common.ServerAddress, common.KeyServerAddress, "", "gRPC server address")
	flags.DurationVar(&common.Timeout, common.KeyTimeout, 30*time.Second, "Connection timeout")
	flags.IntVar(&common.Retries, common.KeyRetries, 1, "Connection retries with exponential backoff")
	return rootCmd
}
