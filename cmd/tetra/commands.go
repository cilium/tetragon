// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/explain"
	"github.com/cilium/tetragon/cmd/tetra/getevents"
	"github.com/cilium/tetragon/cmd/tetra/rthooks"
	"github.com/cilium/tetragon/cmd/tetra/sensors"
	"github.com/cilium/tetragon/cmd/tetra/stacktracetree"
	"github.com/cilium/tetragon/cmd/tetra/status"
	"github.com/cilium/tetragon/cmd/tetra/version"
)

// addBaseCommands adds commands that build and make sense on all platform:
// getevents, version, sensors, stacktracetree, status, rthooks
func addBaseCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(version.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(status.New())
	rootCmd.AddCommand(rthooks.New())
	rootCmd.AddCommand(explain.New())

	// bugtool technically builds on darwin and windows but makes no sense since
	// it's supposed to be run on the machine running Tetragon, using
	// Linux-specific files and tools like bpftool
	// rootCmd.AddCommand(bugtool.New())

	// dump was excluded because it imports the policyfilter package that
	// imports the bpf package that contains unix-specific definitions not found
	// on darwin or windows. Also dump requires CGO on Linux because of the bpf
	// package.
	// rootCmd.AddCommand(dump.New())

	// tracingpolicy does not build on windows because of unix-specific
	// constants used in the kernels package
	// rootCmd.AddCommand(tracingpolicy.New())
}
