// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/operator/crd"
	operatorOption "github.com/cilium/tetragon/operator/option"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, args []string) {
			// Populate option.Config with options from CLI.
			configPopulate()
			cmdRefDir := viper.GetString(operatorOption.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}
			crd.RegisterCRDs()
		},
	}
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
