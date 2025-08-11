// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/loglevel"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(loglevel.New())
}
