// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build standalone

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/getevents"
	"github.com/cilium/tetragon/cmd/tetra/version"
	"github.com/spf13/cobra"
)

// addCommands in standalone mode only supports getevents and version subcommands.
func addCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(version.New())
}
