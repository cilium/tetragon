// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/dump"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/spf13/cobra"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(dump.New())
}
