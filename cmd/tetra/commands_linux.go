// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/cri"
	"github.com/cilium/tetragon/cmd/tetra/debug"
	"github.com/cilium/tetragon/cmd/tetra/dump"
	"github.com/cilium/tetragon/cmd/tetra/loglevel"
	"github.com/cilium/tetragon/cmd/tetra/policyfilter"
	"github.com/cilium/tetragon/cmd/tetra/probe"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/spf13/cobra"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(dump.New())
	rootCmd.AddCommand(debug.New())
	rootCmd.AddCommand(policyfilter.New())
	rootCmd.AddCommand(probe.New())
	rootCmd.AddCommand(loglevel.New())
	rootCmd.AddCommand(cri.New())
}
