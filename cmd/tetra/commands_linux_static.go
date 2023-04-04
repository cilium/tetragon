// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux && standalone

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/spf13/cobra"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(tracingpolicy.New())
}
