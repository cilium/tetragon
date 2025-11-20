// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/explain"
	"github.com/cilium/tetragon/cmd/tetra/loglevel"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(loglevel.New())
	rootCmd.AddCommand(explain.New())
}
