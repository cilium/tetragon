// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/cgtracker"
	"github.com/cilium/tetragon/cmd/tetra/cri"
	"github.com/cilium/tetragon/cmd/tetra/debug"
	"github.com/cilium/tetragon/cmd/tetra/loglevel"
	"github.com/cilium/tetragon/cmd/tetra/policyfilter"
	"github.com/cilium/tetragon/cmd/tetra/probe"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New().Command())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(debug.New())
	rootCmd.AddCommand(debug.NewDumpAlias())
	rootCmd.AddCommand(policyfilter.New())
	rootCmd.AddCommand(probe.New())
	rootCmd.AddCommand(loglevel.New())
	rootCmd.AddCommand(cri.New())
	rootCmd.AddCommand(cgtracker.New())
}
